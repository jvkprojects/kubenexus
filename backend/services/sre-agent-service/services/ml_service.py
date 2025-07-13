"""
Machine Learning service for KubeNexus SRE Agent.
Handles anomaly detection, predictive analytics, and intelligent recommendations.
"""

import numpy as np
import pandas as pd
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import joblib
import asyncio
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from shared import get_logger, get_settings

logger = get_logger(__name__)
settings = get_settings()


class MLService:
    """Machine Learning service for SRE operations."""
    
    _models = {}
    _scalers = {}
    _initialized = False
    
    @classmethod
    async def initialize_models(cls):
        """Initialize ML models for anomaly detection and predictions."""
        
        try:
            logger.info("Initializing ML models...")
            
            # Initialize anomaly detection model
            cls._models['anomaly_detector'] = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            
            # Initialize clustering model for pattern analysis
            cls._models['pattern_analyzer'] = DBSCAN(
                eps=0.5,
                min_samples=5
            )
            
            # Initialize scalers
            cls._scalers['metrics_scaler'] = StandardScaler()
            cls._scalers['resource_scaler'] = StandardScaler()
            
            # Load pre-trained models if available
            await cls._load_pretrained_models()
            
            cls._initialized = True
            logger.info("ML models initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}", exc_info=True)
            raise
    
    @classmethod
    async def get_model_status(cls) -> Dict[str, Dict[str, Any]]:
        """Get status of all ML models."""
        
        if not cls._initialized:
            return {"error": {"status": "not_initialized"}}
        
        status = {}
        for model_name, model in cls._models.items():
            status[model_name] = {
                "status": "loaded",
                "type": type(model).__name__,
                "parameters": getattr(model, 'get_params', lambda: {})()
            }
        
        return status
    
    @classmethod
    async def detect_anomalies(cls, metrics_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomalies in cluster metrics."""
        
        try:
            if not cls._initialized:
                await cls.initialize_models()
            
            # Prepare data for anomaly detection
            features = cls._prepare_features(metrics_data)
            
            if len(features) < 10:  # Need minimum samples
                return {
                    "anomalies": [],
                    "confidence": 0.0,
                    "message": "Insufficient data for anomaly detection"
                }
            
            # Scale features
            features_scaled = cls._scalers['metrics_scaler'].fit_transform(features)
            
            # Detect anomalies
            anomaly_scores = cls._models['anomaly_detector'].fit_predict(features_scaled)
            decision_scores = cls._models['anomaly_detector'].decision_function(features_scaled)
            
            # Identify anomalous points
            anomalies = []
            for i, (score, decision) in enumerate(zip(anomaly_scores, decision_scores)):
                if score == -1:  # Anomaly detected
                    anomalies.append({
                        "index": i,
                        "timestamp": metrics_data.get("timestamps", [])[i] if i < len(metrics_data.get("timestamps", [])) else None,
                        "anomaly_score": float(decision),
                        "severity": cls._calculate_severity(decision),
                        "affected_metrics": cls._identify_affected_metrics(features[i], metrics_data)
                    })
            
            # Calculate overall confidence
            confidence = cls._calculate_confidence(anomaly_scores, decision_scores)
            
            return {
                "anomalies": anomalies,
                "confidence": confidence,
                "total_points": len(features),
                "anomaly_count": len(anomalies),
                "model_info": {
                    "contamination": cls._models['anomaly_detector'].contamination,
                    "estimators": cls._models['anomaly_detector'].n_estimators
                }
            }
            
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}", exc_info=True)
            return {
                "anomalies": [],
                "confidence": 0.0,
                "error": str(e)
            }
    
    @classmethod
    async def analyze_patterns(cls, historical_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze patterns in cluster behavior."""
        
        try:
            if not cls._initialized:
                await cls.initialize_models()
            
            # Prepare data for pattern analysis
            features = cls._prepare_features(historical_data)
            
            if len(features) < 20:  # Need sufficient data for pattern analysis
                return {
                    "patterns": [],
                    "message": "Insufficient data for pattern analysis"
                }
            
            # Scale features
            features_scaled = cls._scalers['resource_scaler'].fit_transform(features)
            
            # Perform clustering
            clusters = cls._models['pattern_analyzer'].fit_predict(features_scaled)
            
            # Analyze clusters
            patterns = cls._analyze_clusters(clusters, features, historical_data)
            
            return {
                "patterns": patterns,
                "cluster_count": len(set(clusters)) - (1 if -1 in clusters else 0),  # Exclude noise
                "noise_points": list(clusters).count(-1),
                "total_points": len(features)
            }
            
        except Exception as e:
            logger.error(f"Pattern analysis failed: {e}", exc_info=True)
            return {
                "patterns": [],
                "error": str(e)
            }
    
    @classmethod
    async def generate_recommendations(cls, cluster_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate intelligent recommendations based on cluster analysis."""
        
        try:
            recommendations = []
            
            # Analyze resource utilization
            resource_recommendations = cls._analyze_resource_utilization(cluster_data)
            recommendations.extend(resource_recommendations)
            
            # Analyze performance metrics
            performance_recommendations = cls._analyze_performance_metrics(cluster_data)
            recommendations.extend(performance_recommendations)
            
            # Analyze security posture
            security_recommendations = cls._analyze_security_posture(cluster_data)
            recommendations.extend(security_recommendations)
            
            # Analyze cost optimization opportunities
            cost_recommendations = cls._analyze_cost_optimization(cluster_data)
            recommendations.extend(cost_recommendations)
            
            # Sort by priority and confidence
            recommendations.sort(key=lambda x: (x['priority_score'], x['confidence']), reverse=True)
            
            return recommendations[:10]  # Return top 10 recommendations
            
        except Exception as e:
            logger.error(f"Recommendation generation failed: {e}", exc_info=True)
            return []
    
    @classmethod
    async def predict_scaling_needs(cls, metrics_history: Dict[str, Any]) -> Dict[str, Any]:
        """Predict future scaling needs based on historical trends."""
        
        try:
            # Simple trend analysis for demonstration
            cpu_data = metrics_history.get('cpu_usage', [])
            memory_data = metrics_history.get('memory_usage', [])
            
            if len(cpu_data) < 10 or len(memory_data) < 10:
                return {
                    "predictions": {},
                    "message": "Insufficient historical data for predictions"
                }
            
            # Calculate trends
            cpu_trend = cls._calculate_trend(cpu_data)
            memory_trend = cls._calculate_trend(memory_data)
            
            # Generate predictions
            predictions = {
                "cpu": {
                    "current_avg": np.mean(cpu_data[-5:]),
                    "predicted_1h": cpu_data[-1] + cpu_trend,
                    "predicted_24h": cpu_data[-1] + (cpu_trend * 24),
                    "trend": "increasing" if cpu_trend > 0 else "decreasing",
                    "confidence": min(0.9, abs(cpu_trend) * 10)
                },
                "memory": {
                    "current_avg": np.mean(memory_data[-5:]),
                    "predicted_1h": memory_data[-1] + memory_trend,
                    "predicted_24h": memory_data[-1] + (memory_trend * 24),
                    "trend": "increasing" if memory_trend > 0 else "decreasing",
                    "confidence": min(0.9, abs(memory_trend) * 10)
                }
            }
            
            # Generate scaling recommendations
            scaling_recommendations = []
            
            if predictions["cpu"]["predicted_24h"] > 80:
                scaling_recommendations.append({
                    "type": "scale_up",
                    "resource": "cpu",
                    "reason": "CPU usage predicted to exceed 80%",
                    "urgency": "high" if predictions["cpu"]["predicted_1h"] > 80 else "medium"
                })
            
            if predictions["memory"]["predicted_24h"] > 85:
                scaling_recommendations.append({
                    "type": "scale_up",
                    "resource": "memory",
                    "reason": "Memory usage predicted to exceed 85%",
                    "urgency": "high" if predictions["memory"]["predicted_1h"] > 85 else "medium"
                })
            
            return {
                "predictions": predictions,
                "scaling_recommendations": scaling_recommendations,
                "model_accuracy": "basic_trend_analysis"
            }
            
        except Exception as e:
            logger.error(f"Scaling prediction failed: {e}", exc_info=True)
            return {
                "predictions": {},
                "error": str(e)
            }
    
    @classmethod
    def _prepare_features(cls, data: Dict[str, Any]) -> np.ndarray:
        """Prepare feature matrix from metrics data."""
        
        # Extract numeric features from metrics data
        features = []
        
        # CPU metrics
        cpu_usage = data.get('cpu_usage', [])
        memory_usage = data.get('memory_usage', [])
        network_io = data.get('network_io', [])
        disk_io = data.get('disk_io', [])
        
        # Ensure all arrays have the same length
        min_length = min(len(arr) for arr in [cpu_usage, memory_usage, network_io, disk_io] if arr)
        
        if min_length == 0:
            return np.array([])
        
        for i in range(min_length):
            feature_vector = [
                cpu_usage[i] if i < len(cpu_usage) else 0,
                memory_usage[i] if i < len(memory_usage) else 0,
                network_io[i] if i < len(network_io) else 0,
                disk_io[i] if i < len(disk_io) else 0
            ]
            features.append(feature_vector)
        
        return np.array(features)
    
    @classmethod
    def _calculate_severity(cls, decision_score: float) -> str:
        """Calculate anomaly severity based on decision score."""
        
        if decision_score < -0.5:
            return "critical"
        elif decision_score < -0.2:
            return "high"
        elif decision_score < -0.1:
            return "medium"
        else:
            return "low"
    
    @classmethod
    def _identify_affected_metrics(cls, feature_vector: np.ndarray, metrics_data: Dict[str, Any]) -> List[str]:
        """Identify which metrics are most affected in an anomaly."""
        
        metric_names = ['cpu_usage', 'memory_usage', 'network_io', 'disk_io']
        affected = []
        
        # Simple heuristic: if feature value is in top/bottom 10%, consider it affected
        for i, value in enumerate(feature_vector):
            if i < len(metric_names):
                metric_data = metrics_data.get(metric_names[i], [])
                if metric_data:
                    percentile_90 = np.percentile(metric_data, 90)
                    percentile_10 = np.percentile(metric_data, 10)
                    
                    if value > percentile_90 or value < percentile_10:
                        affected.append(metric_names[i])
        
        return affected
    
    @classmethod
    def _calculate_confidence(cls, anomaly_scores: np.ndarray, decision_scores: np.ndarray) -> float:
        """Calculate confidence in anomaly detection results."""
        
        anomaly_count = len(anomaly_scores[anomaly_scores == -1])
        total_count = len(anomaly_scores)
        
        if total_count == 0:
            return 0.0
        
        # Confidence based on consistency of decision scores
        score_std = np.std(decision_scores)
        confidence = max(0.0, min(1.0, 1.0 - score_std))
        
        return confidence
    
    @classmethod
    def _analyze_clusters(cls, clusters: np.ndarray, features: np.ndarray, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze identified clusters for patterns."""
        
        patterns = []
        unique_clusters = set(clusters)
        
        for cluster_id in unique_clusters:
            if cluster_id == -1:  # Skip noise
                continue
            
            cluster_indices = np.where(clusters == cluster_id)[0]
            cluster_features = features[cluster_indices]
            
            # Calculate cluster characteristics
            pattern = {
                "cluster_id": int(cluster_id),
                "size": len(cluster_indices),
                "characteristics": {
                    "avg_cpu": float(np.mean(cluster_features[:, 0])),
                    "avg_memory": float(np.mean(cluster_features[:, 1])),
                    "avg_network": float(np.mean(cluster_features[:, 2])),
                    "avg_disk": float(np.mean(cluster_features[:, 3]))
                },
                "pattern_type": cls._classify_pattern(cluster_features)
            }
            
            patterns.append(pattern)
        
        return patterns
    
    @classmethod
    def _classify_pattern(cls, cluster_features: np.ndarray) -> str:
        """Classify the type of pattern in a cluster."""
        
        avg_cpu = np.mean(cluster_features[:, 0])
        avg_memory = np.mean(cluster_features[:, 1])
        
        if avg_cpu > 80 and avg_memory > 80:
            return "high_resource_usage"
        elif avg_cpu < 20 and avg_memory < 20:
            return "low_resource_usage"
        elif np.std(cluster_features, axis=0).mean() > 20:
            return "high_variability"
        else:
            return "normal_operation"
    
    @classmethod
    def _analyze_resource_utilization(cls, cluster_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze resource utilization and generate recommendations."""
        
        recommendations = []
        
        cpu_usage = cluster_data.get('cpu_usage_avg', 0)
        memory_usage = cluster_data.get('memory_usage_avg', 0)
        
        if cpu_usage > 80:
            recommendations.append({
                "type": "resource_optimization",
                "category": "cpu",
                "title": "High CPU Usage Detected",
                "description": f"CPU usage is at {cpu_usage}%. Consider scaling up or optimizing workloads.",
                "priority_score": 8,
                "confidence": 0.9,
                "actions": ["Scale cluster", "Optimize workloads", "Review resource limits"]
            })
        
        if memory_usage > 85:
            recommendations.append({
                "type": "resource_optimization",
                "category": "memory",
                "title": "High Memory Usage Detected",
                "description": f"Memory usage is at {memory_usage}%. Risk of OOM conditions.",
                "priority_score": 9,
                "confidence": 0.95,
                "actions": ["Scale cluster", "Optimize memory usage", "Review memory limits"]
            })
        
        return recommendations
    
    @classmethod
    def _analyze_performance_metrics(cls, cluster_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze performance metrics and generate recommendations."""
        
        recommendations = []
        
        response_time = cluster_data.get('avg_response_time', 0)
        error_rate = cluster_data.get('error_rate', 0)
        
        if response_time > 500:  # milliseconds
            recommendations.append({
                "type": "performance_optimization",
                "category": "latency",
                "title": "High Response Time Detected",
                "description": f"Average response time is {response_time}ms. Consider optimization.",
                "priority_score": 7,
                "confidence": 0.8,
                "actions": ["Optimize queries", "Add caching", "Review network latency"]
            })
        
        if error_rate > 5:  # percentage
            recommendations.append({
                "type": "reliability",
                "category": "errors",
                "title": "High Error Rate Detected",
                "description": f"Error rate is {error_rate}%. Investigate and fix issues.",
                "priority_score": 9,
                "confidence": 0.9,
                "actions": ["Review logs", "Fix error conditions", "Improve error handling"]
            })
        
        return recommendations
    
    @classmethod
    def _analyze_security_posture(cls, cluster_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze security posture and generate recommendations."""
        
        recommendations = []
        
        # Mock security analysis
        pod_security_violations = cluster_data.get('pod_security_violations', 0)
        rbac_issues = cluster_data.get('rbac_issues', 0)
        
        if pod_security_violations > 0:
            recommendations.append({
                "type": "security",
                "category": "pod_security",
                "title": "Pod Security Violations Found",
                "description": f"{pod_security_violations} pods have security violations.",
                "priority_score": 8,
                "confidence": 0.85,
                "actions": ["Review pod security policies", "Fix security contexts", "Enable admission controllers"]
            })
        
        return recommendations
    
    @classmethod
    def _analyze_cost_optimization(cls, cluster_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze cost optimization opportunities."""
        
        recommendations = []
        
        # Mock cost analysis
        unused_resources = cluster_data.get('unused_resource_percentage', 0)
        
        if unused_resources > 30:
            recommendations.append({
                "type": "cost_optimization",
                "category": "resource_efficiency",
                "title": "Unused Resources Detected",
                "description": f"{unused_resources}% of resources are unused. Consider rightsizing.",
                "priority_score": 6,
                "confidence": 0.7,
                "actions": ["Rightsize nodes", "Optimize resource requests", "Consider spot instances"]
            })
        
        return recommendations
    
    @classmethod
    def _calculate_trend(cls, data: List[float]) -> float:
        """Calculate simple linear trend in data."""
        
        if len(data) < 2:
            return 0.0
        
        x = np.arange(len(data))
        y = np.array(data)
        
        # Simple linear regression
        slope = np.corrcoef(x, y)[0, 1] * (np.std(y) / np.std(x))
        
        return slope
    
    @classmethod
    async def _load_pretrained_models(cls):
        """Load pre-trained models from storage if available."""
        
        try:
            # In a real implementation, load models from persistent storage
            # For now, we'll use freshly initialized models
            logger.info("Using freshly initialized models (no pre-trained models found)")
            
        except Exception as e:
            logger.warning(f"Could not load pre-trained models: {e}")
    
    @classmethod
    async def save_models(cls):
        """Save trained models to persistent storage."""
        
        try:
            # In a real implementation, save models to persistent storage
            logger.info("Model saving not implemented (using in-memory models)")
            
        except Exception as e:
            logger.error(f"Failed to save models: {e}", exc_info=True) 