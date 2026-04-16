from datetime import datetime
from app import db
from app.models.audit_log import AuditLog


class AuditService:

    @staticmethod
    def log(
        api_key_id: int,
        method: str,
        path: str,
        request_body: str,
        response_status: int,
        client_ip: str,
        user_agent: str
    ):
        """Log een API request naar audit_logs."""
        log_entry = AuditLog(
            api_key_id=api_key_id,
            method=method,
            path=path,
            request_body=request_body,
            response_status=response_status,
            client_ip=client_ip,
            user_agent=user_agent,
            timestamp=datetime.utcnow()
        )
        db.session.add(log_entry)
        db.session.commit()
