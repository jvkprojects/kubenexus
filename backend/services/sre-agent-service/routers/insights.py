"""
Insights router for KubeNexus SRE Agent Service.
Provides performance insights, analytics, and cluster health overviews.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc
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
class ClusterHealthInsight(BaseModel):
    cluster_id: UUID
    cluster_name: str
    health_score: float
    total_problems: int
    critical_problems: int
    resolved_problems: int
    avg_resolution_time_hours: Optional[float]
    top_problem_types: List[Dict[str, Any]]
    trend: str  # "improving", "stable", "declining"


class PerformanceInsight(BaseModel):
    metric_name: str
    current_value: float
    baseline_value: float
    deviation_percentage: float
    status: str  # "normal", "warning", "critical"
    recommendation: Optional[str]


class ProblemTrendInsight(BaseModel):
    period: str
    problem_count: int
    resolved_count: int
    resolution_rate: float
    avg_resolution_time_hours: float
    most_common_types: List[Dict[str, int]]


class ClusterInsightsResponse(BaseModel):
    cluster_health: ClusterHealthInsight
    performance_insights: List[PerformanceInsight]
    problem_trends: List[ProblemTrendInsight]
    recommendations_summary: Dict[str, Any]
    generated_at: datetime


class OverallInsightsResponse(BaseModel):
    total_clusters: int
    healthy_clusters: int
    clusters_with_issues: int
    total_problems_last_24h: int
    resolution_rate: float
    top_performing_clusters: List[str]
    clusters_needing_attention: List[str]
    insights: List[Dict[str, Any]]
    generated_at: datetime


@router.get("/cluster/{cluster_id}", response_model=ClusterInsightsResponse)
async def get_cluster_insights(
    cluster_id: UUID,
    days: int = Query(7, ge=1, le=90, description="Number of days to analyze"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permissions("sre.insights.read"))
):
    """Get comprehensive insights for a specific cluster."""
    
    try:
        # Verify cluster exists
        result = await db.execute(
            select(KubernetesCluster).where(KubernetesCluster.id == cluster_id)
        )
        cluster = result.scalar_one_or_none()
        
        if not cluster:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cluster not found"
            )
        
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)
        
        # Get cluster health data
        health_insight = await _get_cluster_health_insight(db, cluster, start_date, end_date)
        
        # Get performance insights (mock data for now)
        performance_insights = await _get_performance_insights(cluster_id)
        
        # Get problem trends
        problem_trends = await _get_problem_trends(db, cluster_id, start_date, end_date)
        
        # Get recommendations summary
        recommendations_summary = await _get_recommendations_summary(db, cluster_id)
        
        return ClusterInsightsResponse(
            cluster_health=health_insight,
            performance_insights=performance_insights,
            problem_trends=problem_trends,
            recommendations_summary=recommendations_summary,
            generated_at=datetime.now(timezone.utc)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get cluster insights: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get cluster insights: {str(e)}"
        )


@router.get("/overview", response_model=OverallInsightsResponse)
async def get_overall_insights(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permissions("sre.insights.overview"))
):
    """Get overall insights across all clusters."""
    
    try:
        # Get all clusters
        clusters_result = await db.execute(select(KubernetesCluster))
        clusters = clusters_result.scalars().all()
        
        total_clusters = len(clusters)
        healthy_clusters = sum(1 for c in clusters if c.status == 'connected')
        clusters_with_issues = total_clusters - healthy_clusters
        
        # Get problems from last 24 hours
        yesterday = datetime.now(timezone.utc) - timedelta(hours=24)
        problems_result = await db.execute(
            select(func.count(ProblemApplication.id))
            .where(ProblemApplication.detected_at >= yesterday)
        )
        total_problems_last_24h = problems_result.scalar() or 0
        
        # Calculate resolution rate
        resolved_problems_result = await db.execute(
            select(func.count(ProblemApplication.id))
            .where(
                and_(
                    ProblemApplication.detected_at >= yesterday,
                    ProblemApplication.resolved_at.isnot(None)
                )
            )
        )
        resolved_problems = resolved_problems_result.scalar() or 0
        resolution_rate = (resolved_problems / total_problems_last_24h * 100) if total_problems_last_24h > 0 else 100.0
        
        # Get top performing clusters (least problems)
        top_clusters_result = await db.execute(
            select(
                KubernetesCluster.name,
                func.count(ProblemApplication.id).label('problem_count')
            )
            .outerjoin(ProblemApplication)
            .where(
                or_(
                    ProblemApplication.detected_at >= yesterday,
                    ProblemApplication.id.is_(None)
                )
            )
            .group_by(KubernetesCluster.id, KubernetesCluster.name)
            .order_by(func.count(ProblemApplication.id))
            .limit(5)
        )
        top_performing_clusters = [row[0] for row in top_clusters_result.all()]
        
        # Get clusters needing attention (most problems)
        attention_clusters_result = await db.execute(
            select(
                KubernetesCluster.name,
                func.count(ProblemApplication.id).label('problem_count')
            )
            .join(ProblemApplication)
            .where(ProblemApplication.detected_at >= yesterday)
            .group_by(KubernetesCluster.id, KubernetesCluster.name)
            .order_by(desc(func.count(ProblemApplication.id)))
            .limit(3)
        )
        clusters_needing_attention = [row[0] for row in attention_clusters_result.all()]
        
        # Generate general insights
        insights = []
        
        if resolution_rate >= 90:
            insights.append({
                "type": "positive",
                "title": "Excellent Resolution Rate",
                "description": f"Your teams are resolving {resolution_rate:.1f}% of issues within 24 hours."
            })
        elif resolution_rate < 70:
            insights.append({
                "type": "warning",
                "title": "Low Resolution Rate",
                "description": f"Only {resolution_rate:.1f}% of issues are being resolved within 24 hours. Consider reviewing SRE processes."
            })
        
        if clusters_with_issues > total_clusters * 0.3:
            insights.append({
                "type": "warning",
                "title": "Multiple Clusters Need Attention",
                "description": f"{clusters_with_issues} out of {total_clusters} clusters are experiencing issues."
            })
        
        return OverallInsightsResponse(
            total_clusters=total_clusters,
            healthy_clusters=healthy_clusters,
            clusters_with_issues=clusters_with_issues,
            total_problems_last_24h=total_problems_last_24h,
            resolution_rate=resolution_rate,
            top_performing_clusters=top_performing_clusters,
            clusters_needing_attention=clusters_needing_attention,
            insights=insights,
            generated_at=datetime.now(timezone.utc)
        )
        
    except Exception as e:
        logger.error(f"Failed to get overall insights: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get overall insights: {str(e)}"
        )


@router.get("/performance/{cluster_id}")
async def get_performance_analysis(
    cluster_id: UUID,
    metric_type: str = Query("all", description="Type of metrics to analyze"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permissions("sre.insights.performance"))
):
    """Get detailed performance analysis for a cluster."""
    
    try:
        # Verify cluster exists
        result = await db.execute(
            select(KubernetesCluster).where(KubernetesCluster.id == cluster_id)
        )
        cluster = result.scalar_one_or_none()
        
        if not cluster:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cluster not found"
            )
        
        # Generate performance analysis using ML service
        analysis = await MLService.analyze_performance({
            "cluster_id": str(cluster_id),
            "metric_type": metric_type,
            "timeframe": "24h"
        })
        
        return {
            "cluster_id": str(cluster_id),
            "cluster_name": cluster.name,
            "analysis": analysis,
            "generated_at": datetime.now(timezone.utc).isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get performance analysis: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get performance analysis: {str(e)}"
        )


async def _get_cluster_health_insight(
    db: AsyncSession, 
    cluster: KubernetesCluster, 
    start_date: datetime, 
    end_date: datetime
) -> ClusterHealthInsight:
    """Generate cluster health insight."""
    
    # Get problem statistics
    problems_result = await db.execute(
        select(
            func.count(ProblemApplication.id).label('total'),
            func.count(ProblemApplication.id).filter(ProblemApplication.severity == 'critical').label('critical'),
            func.count(ProblemApplication.id).filter(ProblemApplication.resolved_at.isnot(None)).label('resolved')
        )
        .where(
            and_(
                ProblemApplication.cluster_id == cluster.id,
                ProblemApplication.detected_at >= start_date
            )
        )
    )
    stats = problems_result.first()
    
    total_problems = stats.total or 0
    critical_problems = stats.critical or 0
    resolved_problems = stats.resolved or 0
    
    # Calculate average resolution time
    avg_resolution_result = await db.execute(
        select(
            func.avg(
                func.extract('epoch', ProblemApplication.resolved_at - ProblemApplication.detected_at) / 3600
            )
        )
        .where(
            and_(
                ProblemApplication.cluster_id == cluster.id,
                ProblemApplication.resolved_at.isnot(None),
                ProblemApplication.detected_at >= start_date
            )
        )
    )
    avg_resolution_time = avg_resolution_result.scalar()
    
    # Get top problem types
    problem_types_result = await db.execute(
        select(
            ProblemApplication.problem_type,
            func.count(ProblemApplication.id).label('count')
        )
        .where(
            and_(
                ProblemApplication.cluster_id == cluster.id,
                ProblemApplication.detected_at >= start_date
            )
        )
        .group_by(ProblemApplication.problem_type)
        .order_by(desc(func.count(ProblemApplication.id)))
        .limit(5)
    )
    top_problem_types = [
        {"type": row[0], "count": row[1]}
        for row in problem_types_result.all()
    ]
    
    # Calculate health score (0-100)
    health_score = 100.0
    if total_problems > 0:
        resolution_rate = resolved_problems / total_problems
        critical_impact = (critical_problems / total_problems) * 30 if total_problems > 0 else 0
        health_score = max(0, 100 - critical_impact - ((1 - resolution_rate) * 50))
    
    # Determine trend (simplified logic)
    trend = "stable"
    if health_score >= 90:
        trend = "improving"
    elif health_score < 70:
        trend = "declining"
    
    return ClusterHealthInsight(
        cluster_id=cluster.id,
        cluster_name=cluster.name,
        health_score=health_score,
        total_problems=total_problems,
        critical_problems=critical_problems,
        resolved_problems=resolved_problems,
        avg_resolution_time_hours=avg_resolution_time,
        top_problem_types=top_problem_types,
        trend=trend
    )


async def _get_performance_insights(cluster_id: UUID) -> List[PerformanceInsight]:
    """Generate performance insights (mock implementation)."""
    
    # In a real implementation, this would analyze actual metrics
    return [
        PerformanceInsight(
            metric_name="CPU Utilization",
            current_value=75.2,
            baseline_value=65.0,
            deviation_percentage=15.7,
            status="warning",
            recommendation="Consider adding more nodes or optimizing resource requests"
        ),
        PerformanceInsight(
            metric_name="Memory Utilization",
            current_value=82.5,
            baseline_value=70.0,
            deviation_percentage=17.9,
            status="warning",
            recommendation="Review memory limits and identify memory leaks"
        ),
        PerformanceInsight(
            metric_name="Pod Restart Rate",
            current_value=2.1,
            baseline_value=0.5,
            deviation_percentage=320.0,
            status="critical",
            recommendation="Investigate application stability and resource constraints"
        )
    ]


async def _get_problem_trends(
    db: AsyncSession, 
    cluster_id: UUID, 
    start_date: datetime, 
    end_date: datetime
) -> List[ProblemTrendInsight]:
    """Generate problem trend insights."""
    
    trends = []
    current_date = start_date
    
    while current_date < end_date:
        period_end = min(current_date + timedelta(days=1), end_date)
        
        # Get problems for this period
        problems_result = await db.execute(
            select(
                func.count(ProblemApplication.id).label('total'),
                func.count(ProblemApplication.id).filter(ProblemApplication.resolved_at.isnot(None)).label('resolved')
            )
            .where(
                and_(
                    ProblemApplication.cluster_id == cluster_id,
                    ProblemApplication.detected_at >= current_date,
                    ProblemApplication.detected_at < period_end
                )
            )
        )
        stats = problems_result.first()
        
        problem_count = stats.total or 0
        resolved_count = stats.resolved or 0
        resolution_rate = (resolved_count / problem_count * 100) if problem_count > 0 else 100.0
        
        # Get average resolution time for this period
        avg_resolution_result = await db.execute(
            select(
                func.avg(
                    func.extract('epoch', ProblemApplication.resolved_at - ProblemApplication.detected_at) / 3600
                )
            )
            .where(
                and_(
                    ProblemApplication.cluster_id == cluster_id,
                    ProblemApplication.resolved_at.isnot(None),
                    ProblemApplication.detected_at >= current_date,
                    ProblemApplication.detected_at < period_end
                )
            )
        )
        avg_resolution_time = avg_resolution_result.scalar() or 0.0
        
        trends.append(ProblemTrendInsight(
            period=current_date.strftime("%Y-%m-%d"),
            problem_count=problem_count,
            resolved_count=resolved_count,
            resolution_rate=resolution_rate,
            avg_resolution_time_hours=avg_resolution_time,
            most_common_types=[]  # Could be populated with more detailed analysis
        ))
        
        current_date = period_end
    
    return trends


async def _get_recommendations_summary(db: AsyncSession, cluster_id: UUID) -> Dict[str, Any]:
    """Generate recommendations summary."""
    
    # Get recent recommendations
    recommendations_result = await db.execute(
        select(func.count(ResolutionSuggestion.id))
        .join(ProblemApplication)
        .where(ProblemApplication.cluster_id == cluster_id)
    )
    total_recommendations = recommendations_result.scalar() or 0
    
    # Get high confidence recommendations
    high_confidence_result = await db.execute(
        select(func.count(ResolutionSuggestion.id))
        .join(ProblemApplication)
        .where(
            and_(
                ProblemApplication.cluster_id == cluster_id,
                ResolutionSuggestion.confidence_score >= 0.8
            )
        )
    )
    high_confidence_count = high_confidence_result.scalar() or 0
    
    return {
        "total_recommendations": total_recommendations,
        "high_confidence_recommendations": high_confidence_count,
        "confidence_rate": (high_confidence_count / total_recommendations * 100) if total_recommendations > 0 else 0.0
    } 