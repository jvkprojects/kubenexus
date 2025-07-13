"""
Shared logging utilities for KubeNexus backend services.
Provides structured logging configuration and utilities.
"""

import logging
import logging.handlers
import sys
import json
import traceback
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import structlog
from contextlib import contextmanager
import os

from .config import get_settings

settings = get_settings()


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'service': getattr(record, 'service', settings.log_service_name or 'unknown'),
            'version': getattr(record, 'version', settings.log_service_version),
            'environment': getattr(record, 'environment', settings.log_environment),
        }
        
        # Add request context if available
        if hasattr(record, 'request_id'):
            log_entry['request_id'] = record.request_id
        
        if hasattr(record, 'user_id'):
            log_entry['user_id'] = record.user_id
        
        if hasattr(record, 'correlation_id'):
            log_entry['correlation_id'] = record.correlation_id
        
        # Add extra fields
        if hasattr(record, 'extra'):
            log_entry.update(record.extra)
        
        # Add exception information
        if record.exc_info:
            log_entry['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': traceback.format_exception(*record.exc_info)
            }
        
        return json.dumps(log_entry, default=str)


class TextFormatter(logging.Formatter):
    """Enhanced text formatter with context information."""
    
    def __init__(self):
        super().__init__(
            fmt='%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with additional context."""
        # Add context information to the message
        context_parts = []
        
        if hasattr(record, 'request_id'):
            context_parts.append(f"req_id={record.request_id}")
        
        if hasattr(record, 'user_id'):
            context_parts.append(f"user_id={record.user_id}")
        
        if hasattr(record, 'correlation_id'):
            context_parts.append(f"corr_id={record.correlation_id}")
        
        if context_parts:
            record.msg = f"[{' | '.join(context_parts)}] {record.msg}"
        
        return super().format(record)


class RequestContextFilter(logging.Filter):
    """Filter to add request context to log records."""
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Add request context to log record."""
        # Simply return True without context variable processing
        # Context variables will be handled by structlog processors
        return True


class StructlogProcessor:
    """Structlog processor for enhanced logging."""
    
    @staticmethod
    def add_service_info(logger, method_name, event_dict):
        """Add service information to log entry."""
        event_dict.setdefault('service', settings.log_service_name or 'unknown')
        event_dict.setdefault('version', settings.log_service_version)
        event_dict.setdefault('environment', settings.log_environment)
        return event_dict
    
    @staticmethod
    def add_timestamp(logger, method_name, event_dict):
        """Add timestamp to log entry."""
        event_dict['timestamp'] = datetime.now(timezone.utc).isoformat()
        return event_dict
    
    @staticmethod
    def format_exception(logger, method_name, event_dict):
        """Format exception information."""
        if event_dict.get('exc_info'):
            exc_info = event_dict.pop('exc_info')
            if exc_info is True:
                exc_info = sys.exc_info()
            
            if exc_info and exc_info[0]:
                event_dict['exception'] = {
                    'type': exc_info[0].__name__,
                    'message': str(exc_info[1]),
                    'traceback': traceback.format_exception(*exc_info)
                }
        
        return event_dict


def setup_logging(
    service_name: Optional[str] = None,
    log_level: Optional[str] = None,
    log_format: Optional[str] = None,
    log_file: Optional[str] = None
):
    """Setup logging configuration for a service."""
    
    # Use provided values or fall back to settings
    service_name = service_name or settings.log_service_name or 'kubenexus'
    log_level = log_level or settings.log_level
    log_format = log_format or settings.log_format
    log_file = log_file or settings.log_file
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear any existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, log_level.upper()))
    
    # File handler (if specified)
    file_handler = None
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=settings.log_max_size,
            backupCount=settings.log_backup_count
        )
        file_handler.setLevel(getattr(logging, log_level.upper()))
    
    # Choose formatter based on format setting
    if log_format.lower() == 'json':
        formatter = JSONFormatter()
    else:
        formatter = TextFormatter()
    
    # Apply formatter to handlers
    console_handler.setFormatter(formatter)
    if file_handler:
        file_handler.setFormatter(formatter)
    
    # Add context filter
    context_filter = RequestContextFilter()
    console_handler.addFilter(context_filter)
    if file_handler:
        file_handler.addFilter(context_filter)
    
    # Add handlers to root logger
    root_logger.addHandler(console_handler)
    if file_handler:
        root_logger.addHandler(file_handler)
    
    # Configure structlog
    structlog.configure(
        processors=[
            StructlogProcessor.add_service_info,
            StructlogProcessor.add_timestamp,
            StructlogProcessor.format_exception,
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.CallsiteParameterAdder(
                parameters=[structlog.processors.CallsiteParameter.FILENAME,
                           structlog.processors.CallsiteParameter.FUNC_NAME,
                           structlog.processors.CallsiteParameter.LINENO]
            ),
            structlog.processors.TimeStamper(fmt="ISO"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # Set service name in logger context
    logger = structlog.get_logger(service_name)
    
    # Log initialization
    logger.info(
        "Logging initialized",
        service=service_name,
        level=log_level,
        format=log_format,
        file=log_file
    )
    
    return logger


def get_logger(name: str = None) -> structlog.stdlib.BoundLogger:
    """Get a configured logger instance."""
    return structlog.get_logger(name)


class LogContext:
    """Context manager for adding context to logs."""
    
    def __init__(self, **context):
        self.context = context
        self.original_context = {}
    
    def __enter__(self):
        """Enter context and bind additional context."""
        # Store original context values
        try:
            from contextvars import copy_context
            self.original_context = copy_context()
        except ImportError:
            pass
        
        # Bind new context
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(**self.context)
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context and restore original context."""
        # Restore original context
        structlog.contextvars.clear_contextvars()
        if hasattr(structlog.contextvars, 'bind_contextvars') and self.original_context:
            try:
                structlog.contextvars.bind_contextvars(**self.original_context)
            except:
                pass


@contextmanager
def log_context(**context):
    """Context manager for temporary log context."""
    with LogContext(**context):
        yield


def log_function_call(func):
    """Decorator to log function calls."""
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        
        # Log function entry
        logger.debug(
            "Function called",
            function=func.__name__,
            module=func.__module__,
            args=len(args),
            kwargs=list(kwargs.keys())
        )
        
        try:
            result = func(*args, **kwargs)
            
            # Log successful completion
            logger.debug(
                "Function completed",
                function=func.__name__,
                module=func.__module__
            )
            
            return result
            
        except Exception as e:
            # Log exception
            logger.error(
                "Function failed",
                function=func.__name__,
                module=func.__module__,
                error=str(e),
                exc_info=True
            )
            raise
    
    return wrapper


def log_async_function_call(func):
    """Decorator to log async function calls."""
    async def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        
        # Log function entry
        logger.debug(
            "Async function called",
            function=func.__name__,
            module=func.__module__,
            args=len(args),
            kwargs=list(kwargs.keys())
        )
        
        try:
            result = await func(*args, **kwargs)
            
            # Log successful completion
            logger.debug(
                "Async function completed",
                function=func.__name__,
                module=func.__module__
            )
            
            return result
            
        except Exception as e:
            # Log exception
            logger.error(
                "Async function failed",
                function=func.__name__,
                module=func.__module__,
                error=str(e),
                exc_info=True
            )
            raise
    
    return wrapper


class PerformanceLogger:
    """Logger for performance metrics."""
    
    def __init__(self, operation: str, logger: Optional[structlog.stdlib.BoundLogger] = None):
        self.operation = operation
        self.logger = logger or get_logger(__name__)
        self.start_time = None
    
    def __enter__(self):
        """Start performance measurement."""
        self.start_time = datetime.now(timezone.utc)
        self.logger.debug(
            "Operation started",
            operation=self.operation,
            start_time=self.start_time.isoformat()
        )
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """End performance measurement and log results."""
        end_time = datetime.now(timezone.utc)
        duration = (end_time - self.start_time).total_seconds()
        
        if exc_type:
            self.logger.error(
                "Operation failed",
                operation=self.operation,
                duration_seconds=duration,
                error=str(exc_val),
                exc_info=True
            )
        else:
            self.logger.info(
                "Operation completed",
                operation=self.operation,
                duration_seconds=duration,
                end_time=end_time.isoformat()
            )


def performance_log(operation: str):
    """Context manager for performance logging."""
    return PerformanceLogger(operation)


class AuditLogger:
    """Specialized logger for audit events."""
    
    def __init__(self):
        self.logger = get_logger("audit")
    
    def log_user_action(
        self,
        user_id: str,
        action: str,
        resource_type: str,
        resource_name: str,
        cluster_id: Optional[str] = None,
        namespace: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ):
        """Log user action for audit purposes."""
        
        log_data = {
            'event_type': 'user_action',
            'user_id': user_id,
            'action': action,
            'resource_type': resource_type,
            'resource_name': resource_name,
            'success': success,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        if cluster_id:
            log_data['cluster_id'] = cluster_id
        
        if namespace:
            log_data['namespace'] = namespace
        
        if error_message:
            log_data['error_message'] = error_message
        
        if additional_data:
            log_data.update(additional_data)
        
        if success:
            self.logger.info("User action completed", **log_data)
        else:
            self.logger.warning("User action failed", **log_data)
    
    def log_system_event(
        self,
        event_type: str,
        description: str,
        severity: str = "info",
        additional_data: Optional[Dict[str, Any]] = None
    ):
        """Log system event for audit purposes."""
        
        log_data = {
            'event_type': 'system_event',
            'description': description,
            'severity': severity,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        if additional_data:
            log_data.update(additional_data)
        
        log_method = getattr(self.logger, severity.lower(), self.logger.info)
        log_method(f"System event: {event_type}", **log_data)


class SecurityLogger:
    """Specialized logger for security events."""
    
    def __init__(self):
        self.logger = get_logger("security")
    
    def log_authentication_attempt(
        self,
        username: str,
        success: bool,
        ip_address: str,
        user_agent: str,
        auth_method: str = "local",
        failure_reason: Optional[str] = None
    ):
        """Log authentication attempt."""
        
        log_data = {
            'event_type': 'authentication',
            'username': username,
            'success': success,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'auth_method': auth_method,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        if failure_reason:
            log_data['failure_reason'] = failure_reason
        
        if success:
            self.logger.info("Authentication successful", **log_data)
        else:
            self.logger.warning("Authentication failed", **log_data)
    
    def log_authorization_failure(
        self,
        user_id: str,
        resource: str,
        action: str,
        ip_address: str,
        reason: str
    ):
        """Log authorization failure."""
        
        self.logger.warning(
            "Authorization denied",
            event_type='authorization_failure',
            user_id=user_id,
            resource=resource,
            action=action,
            ip_address=ip_address,
            reason=reason,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
    
    def log_security_event(
        self,
        event_type: str,
        description: str,
        severity: str = "warning",
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ):
        """Log security event."""
        
        log_data = {
            'event_type': f'security_{event_type}',
            'description': description,
            'severity': severity,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        if user_id:
            log_data['user_id'] = user_id
        
        if ip_address:
            log_data['ip_address'] = ip_address
        
        if additional_data:
            log_data.update(additional_data)
        
        log_method = getattr(self.logger, severity.lower(), self.logger.warning)
        log_method(f"Security event: {event_type}", **log_data)


# Global logger instances
audit_logger = AuditLogger()
security_logger = SecurityLogger()


def configure_third_party_loggers():
    """Configure third-party library loggers."""
    
    # Reduce noise from third-party libraries
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('httpx').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)
    
    # Database related loggers
    logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)
    logging.getLogger('sqlalchemy.pool').setLevel(logging.WARNING)
    
    # Redis logger
    logging.getLogger('redis').setLevel(logging.WARNING)
    
    # Kubernetes client logger
    logging.getLogger('kubernetes').setLevel(logging.WARNING)
    logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)


def init_logging(service_name: str) -> structlog.stdlib.BoundLogger:
    """Initialize logging for a service."""
    
    # Setup basic logging
    logger = setup_logging(service_name=service_name)
    
    # Configure third-party loggers
    configure_third_party_loggers()
    
    return logger 