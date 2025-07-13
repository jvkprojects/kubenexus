"""
Recommendations router for KubeNexus SRE Agent Service.
Handles AI-powered recommendations and resolution suggestions.
"""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import joinedload
from pydantic import BaseModel, Field
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared import (
    get_async_db_dependency,
    get_logger,
    ProblemApplication,
    ResolutionSuggestion,
    KubernetesCluster,
    audit_logger,
    require_permissions,
    get_current_user
)
from services.ml_service import MLService

router = APIRouter()
logger = get_logger(__name__)


# Pydantic models
class RecommendationRequest(BaseModel):
    problem_id: Optional[UUID] = None
    cluster_id: Optional[UUID] = None
    problem_description: Optional[str] = None
    resource_type: Optional[str] = None
    namespace: Optional[str] = None
    context_data: Optional[Dict[str, Any]] = {}


class RecommendationResponse(BaseModel):
    id: UUID
    problem_id: UUID
    suggestion_text: str
    command_example: Optional[str]
    documentation_link: Optional[str]
    confidence_score: float
    priority: int
    category: str
    estimated_impact: str
    created_at: datetime


class RecommendationListResponse(BaseModel):
    recommendations: List[RecommendationResponse]
    total_count: int
    page: int
    page_size: int


class GenerateRecommendationsRequest(BaseModel):
    cluster_id: UUID
    problem_type: str
    severity: str
    resource_type: str
    resource_name: str
    namespace: str
    description: str
    metrics_data: Optional[Dict[str, Any]] = {}


@router.post("/generate", response_model=List[RecommendationResponse])
async def generate_recommendations(
    request: GenerateRecommendationsRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permissions("sre.recommendations.generate"))
):
    """Generate AI-powered recommendations for a problem."""
    
    try:
        # Verify cluster exists
        result = await db.execute(
            select(KubernetesCluster).where(KubernetesCluster.id == request.cluster_id)
        )
        cluster = result.scalar_one_or_none()
        
        if not cluster:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cluster not found"
            )
        
        # Create or find existing problem
        problem_result = await db.execute(
            select(ProblemApplication).where(
                and_(
                    ProblemApplication.cluster_id == request.cluster_id,
                    ProblemApplication.resource_name == request.resource_name,
                    ProblemApplication.namespace == request.namespace,
                    ProblemApplication.problem_type == request.problem_type,
                    ProblemApplication.resolved_at.is_(None)
                )
            )
        )
        problem = problem_result.scalar_one_or_none()
        
        if not problem:
            # Create new problem
            problem = ProblemApplication(
                cluster_id=request.cluster_id,
                namespace=request.namespace,
                resource_type=request.resource_type,
                resource_name=request.resource_name,
                problem_type=request.problem_type,
                problem_description=request.description,
                severity=request.severity,
                detection_data=request.metrics_data
            )
            db.add(problem)
            await db.flush()
        
        # Generate recommendations using ML service
        recommendations_data = await MLService.generate_recommendations({
            "problem_type": request.problem_type,
            "severity": request.severity,
            "resource_type": request.resource_type,
            "description": request.description,
            "metrics_data": request.metrics_data
        })
        
        # Save recommendations to database
        recommendations = []
        for i, rec_data in enumerate(recommendations_data.get("recommendations", [])):
            suggestion = ResolutionSuggestion(
                problem_id=problem.id,
                suggestion_text=rec_data.get("text", ""),
                command_example=rec_data.get("command", ""),
                documentation_link=rec_data.get("docs_link", ""),
                confidence_score=rec_data.get("confidence", 0.5),
                priority=i + 1
            )
            db.add(suggestion)
            recommendations.append(suggestion)
        
        await db.commit()
        
        # Convert to response format
        response_recommendations = []
        for suggestion in recommendations:
            response_recommendations.append(RecommendationResponse(
                id=suggestion.id,
                problem_id=suggestion.problem_id,
                suggestion_text=suggestion.suggestion_text,
                command_example=suggestion.command_example,
                documentation_link=suggestion.documentation_link,
                confidence_score=suggestion.confidence_score,
                priority=suggestion.priority,
                category=_categorize_recommendation(suggestion.suggestion_text),
                estimated_impact=_estimate_impact(suggestion.confidence_score),
                created_at=suggestion.created_at
            ))
        
        audit_logger.info(
            "Recommendations generated",
            extra={
                "user_id": current_user["id"],
                "problem_id": str(problem.id),
                "cluster_id": str(request.cluster_id),
                "recommendations_count": len(response_recommendations)
            }
        )
        
        return response_recommendations
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate recommendations: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate recommendations: {str(e)}"
        )


@router.get("/problem/{problem_id}", response_model=List[RecommendationResponse])
async def get_problem_recommendations(
    problem_id: UUID,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permissions("sre.recommendations.read"))
):
    """Get all recommendations for a specific problem."""
    
    try:
        # Verify problem exists
        problem_result = await db.execute(
            select(ProblemApplication).where(ProblemApplication.id == problem_id)
        )
        problem = problem_result.scalar_one_or_none()
        
        if not problem:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Problem not found"
            )
        
        # Get recommendations
        result = await db.execute(
            select(ResolutionSuggestion)
            .where(ResolutionSuggestion.problem_id == problem_id)
            .order_by(ResolutionSuggestion.priority)
        )
        suggestions = result.scalars().all()
        
        # Convert to response format
        recommendations = []
        for suggestion in suggestions:
            recommendations.append(RecommendationResponse(
                id=suggestion.id,
                problem_id=suggestion.problem_id,
                suggestion_text=suggestion.suggestion_text,
                command_example=suggestion.command_example,
                documentation_link=suggestion.documentation_link,
                confidence_score=suggestion.confidence_score,
                priority=suggestion.priority,
                category=_categorize_recommendation(suggestion.suggestion_text),
                estimated_impact=_estimate_impact(suggestion.confidence_score),
                created_at=suggestion.created_at
            ))
        
        return recommendations
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get recommendations: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get recommendations: {str(e)}"
        )


@router.get("/", response_model=RecommendationListResponse)
async def list_recommendations(
    cluster_id: Optional[UUID] = Query(None, description="Filter by cluster ID"),
    category: Optional[str] = Query(None, description="Filter by category"),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum confidence score"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permissions("sre.recommendations.list"))
):
    """List recommendations with filtering and pagination."""
    
    try:
        # Build query with joins
        query = select(ResolutionSuggestion).join(
            ProblemApplication, ResolutionSuggestion.problem_id == ProblemApplication.id
        )
        
        # Apply filters
        conditions = []
        if cluster_id:
            conditions.append(ProblemApplication.cluster_id == cluster_id)
        if min_confidence is not None:
            conditions.append(ResolutionSuggestion.confidence_score >= min_confidence)
        
        if conditions:
            query = query.where(and_(*conditions))
        
        # Count total items
        count_query = select(func.count(ResolutionSuggestion.id)).join(
            ProblemApplication, ResolutionSuggestion.problem_id == ProblemApplication.id
        )
        if conditions:
            count_query = count_query.where(and_(*conditions))
        
        total_result = await db.execute(count_query)
        total_count = total_result.scalar()
        
        # Apply pagination
        offset = (page - 1) * page_size
        query = query.offset(offset).limit(page_size)
        query = query.order_by(ResolutionSuggestion.created_at.desc())
        
        # Execute query
        result = await db.execute(query)
        suggestions = result.scalars().all()
        
        # Convert to response format and apply category filter
        recommendations = []
        for suggestion in suggestions:
            category_name = _categorize_recommendation(suggestion.suggestion_text)
            
            # Apply category filter
            if category and category_name.lower() != category.lower():
                continue
                
            recommendations.append(RecommendationResponse(
                id=suggestion.id,
                problem_id=suggestion.problem_id,
                suggestion_text=suggestion.suggestion_text,
                command_example=suggestion.command_example,
                documentation_link=suggestion.documentation_link,
                confidence_score=suggestion.confidence_score,
                priority=suggestion.priority,
                category=category_name,
                estimated_impact=_estimate_impact(suggestion.confidence_score),
                created_at=suggestion.created_at
            ))
        
        return RecommendationListResponse(
            recommendations=recommendations,
            total_count=total_count,
            page=page,
            page_size=page_size
        )
        
    except Exception as e:
        logger.error(f"Failed to list recommendations: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list recommendations: {str(e)}"
        )


@router.post("/{recommendation_id}/feedback")
async def provide_feedback(
    recommendation_id: UUID,
    feedback: Dict[str, Any],
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permissions("sre.recommendations.feedback"))
):
    """Provide feedback on a recommendation for ML model improvement."""
    
    try:
        # Verify recommendation exists
        result = await db.execute(
            select(ResolutionSuggestion).where(ResolutionSuggestion.id == recommendation_id)
        )
        suggestion = result.scalar_one_or_none()
        
        if not suggestion:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recommendation not found"
            )
        
        # Process feedback (in a real implementation, this would update ML models)
        feedback_data = {
            "recommendation_id": str(recommendation_id),
            "user_id": current_user["id"],
            "feedback": feedback,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # Log feedback for ML model training
        audit_logger.info(
            "Recommendation feedback received",
            extra=feedback_data
        )
        
        return {"message": "Feedback received successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to process feedback: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process feedback: {str(e)}"
        )


def _categorize_recommendation(suggestion_text: str) -> str:
    """Categorize recommendation based on its content."""
    text_lower = suggestion_text.lower()
    
    if any(word in text_lower for word in ["resource", "cpu", "memory", "limit"]):
        return "Resource Management"
    elif any(word in text_lower for word in ["scale", "replica", "hpa"]):
        return "Scaling"
    elif any(word in text_lower for word in ["network", "service", "ingress"]):
        return "Networking"
    elif any(word in text_lower for word in ["security", "rbac", "permission"]):
        return "Security"
    elif any(word in text_lower for word in ["config", "configmap", "secret"]):
        return "Configuration"
    elif any(word in text_lower for word in ["storage", "volume", "pvc"]):
        return "Storage"
    else:
        return "General"


def _estimate_impact(confidence_score: float) -> str:
    """Estimate the impact level based on confidence score."""
    if confidence_score >= 0.8:
        return "High"
    elif confidence_score >= 0.6:
        return "Medium"
    else:
        return "Low" 