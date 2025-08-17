"""
Audit logging utility for "Guards"
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from logging.handlers import RotatingFileHandler
from config.security_config import security_config

class AuditLogger:
    """Audit logger for security events and user actions."""
    
    def __init__(self):
        self.config = security_config.get_audit_logging_config()
        self.logger = self._setup_logger()
        
    def _setup_logger(self) -> logging.Logger:
        """Set up the audit logger.
        
        Returns:
            Configured logger instance
        """
        if not self.config.get('enabled', True):
            return logging.getLogger('audit')
            
        logger = logging.getLogger('audit')
        logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        log_dir = os.path.dirname(self.config.get('log_file', 'logs/security.log'))
        os.makedirs(log_dir, exist_ok=True)
        
        # Set up rotating file handler
        handler = RotatingFileHandler(
            self.config.get('log_file', 'logs/security.log'),
            maxBytes=self.config.get('max_log_size_mb', 100) * 1024 * 1024,
            backupCount=self.config.get('backup_count', 5)
        )
        
        # Set up formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(handler)
        
        return logger
        
    def log_event(self, 
                  event_type: str,
                  user_id: Optional[str] = None,
                  ip_address: Optional[str] = None,
                  details: Optional[Dict[str, Any]] = None):
        """Log an audit event.
        
        Args:
            event_type: Type of event
            user_id: ID of the user who performed the action
            ip_address: IP address of the user
            details: Additional event details
        """
        if not self.config.get('enabled', True):
            return
            
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip_address,
            'details': details or {}
        }
        
        self.logger.info(json.dumps(log_entry))
        
    def log_security_event(self,
                          event_type: str,
                          severity: str,
                          details: Optional[Dict[str, Any]] = None):
        """Log a security event.
        
        Args:
            event_type: Type of security event
            severity: Event severity (INFO, WARNING, ERROR, CRITICAL)
            details: Additional event details
        """
        if not self.config.get('enabled', True):
            return
            
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'severity': severity,
            'details': details or {}
        }
        
        if severity == 'INFO':
            self.logger.info(json.dumps(log_entry))
        elif severity == 'WARNING':
            self.logger.warning(json.dumps(log_entry))
        elif severity == 'ERROR':
            self.logger.error(json.dumps(log_entry))
        elif severity == 'CRITICAL':
            self.logger.critical(json.dumps(log_entry))
            
    def log_user_action(self,
                       user_id: str,
                       action: str,
                       resource: str,
                       status: str,
                       details: Optional[Dict[str, Any]] = None):
        """Log a user action.
        
        Args:
            user_id: ID of the user
            action: Action performed
            resource: Resource affected
            status: Action status (SUCCESS, FAILURE)
            details: Additional action details
        """
        if not self.config.get('enabled', True):
            return
            
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'action': action,
            'resource': resource,
            'status': status,
            'details': details or {}
        }
        
        self.logger.info(json.dumps(log_entry))
        
    def log_api_request(self,
                       method: str,
                       endpoint: str,
                       user_id: Optional[str] = None,
                       ip_address: Optional[str] = None,
                       status_code: Optional[int] = None,
                       details: Optional[Dict[str, Any]] = None):
        """Log an API request.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            user_id: ID of the user making the request
            ip_address: IP address of the request
            status_code: HTTP status code
            details: Additional request details
        """
        if not self.config.get('enabled', True):
            return
            
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'method': method,
            'endpoint': endpoint,
            'user_id': user_id,
            'ip_address': ip_address,
            'status_code': status_code,
            'details': details or {}
        }
        
        self.logger.info(json.dumps(log_entry))
        
    def get_recent_events(self, 
                         event_type: Optional[str] = None,
                         user_id: Optional[str] = None,
                         limit: int = 100) -> list:
        """Get recent audit events.
        
        Args:
            event_type: Filter by event type
            user_id: Filter by user ID
            limit: Maximum number of events to return
            
        Returns:
            List of recent events
        """
        if not self.config.get('enabled', True):
            return []
            
        events = []
        log_file = self.config.get('log_file', 'logs/security.log')
        
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line.split(' - ')[-1])
                        if event_type and event.get('event_type') != event_type:
                            continue
                        if user_id and event.get('user_id') != user_id:
                            continue
                        events.append(event)
                        if len(events) >= limit:
                            break
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass
            
        return events

# Create global audit logger instance
audit_logger = AuditLogger() 