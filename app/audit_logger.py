import logging
from typing import List, Optional
from datetime import datetime
import json
import os
from supabase import create_client, Client

logger = logging.getLogger(__name__)

class SanctionsAuditLogger:
    def __init__(self):
        self.supabase_url = os.getenv("SUPABASE_URL")
        self.supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        self.supabase: Optional[Client] = None
        
        if self.supabase_url and self.supabase_key:
            try:
                self.supabase = create_client(self.supabase_url, self.supabase_key)
                logger.info("Supabase client initialized for audit logging")
            except Exception as e:
                logger.error(f"Failed to initialize Supabase client: {e}")
        else:
            logger.warning("Supabase credentials not found, audit logging will be file-based only")
        
        # Ensure audit log directory exists
        self.audit_log_dir = "audit_logs"
        os.makedirs(self.audit_log_dir, exist_ok=True)
    
    async def log_sanctions_action(
        self,
        partner_id: str,
        action: str,
        address: str,
        risk_score: int,
        risk_factors: List[str],
        data_sources: List[str],
        reason: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> bool:
        """Log sanctions action to both database and file system"""
        
        timestamp = datetime.utcnow().isoformat()
        
        audit_entry = {
            "partner_id": partner_id,
            "action": action,
            "address": address,
            "risk_score": risk_score,
            "risk_factors": risk_factors,
            "data_sources": data_sources,
            "reason": reason,
            "timestamp": timestamp,
            "ip_address": ip_address,
            "user_agent": user_agent
        }
        
        # Log to database if available
        db_success = await self._log_to_database(audit_entry)
        
        # Log to file system as backup
        file_success = self._log_to_file(audit_entry)
        
        if db_success or file_success:
            logger.info(f"Audit log created for {action} on {address} by {partner_id}")
            return True
        else:
            logger.error(f"Failed to log audit entry for {action} on {address}")
            return False
    
    async def _log_to_database(self, audit_entry: dict) -> bool:
        """Log audit entry to Supabase database"""
        if not self.supabase:
            return False
        
        try:
            # Try to insert into sanctions_audit_log table
            response = self.supabase.table("sanctions_audit_log").insert(audit_entry).execute()
            
            if response.data:
                logger.debug(f"Audit entry logged to database: {audit_entry['action']} on {audit_entry['address']}")
                return True
            else:
                logger.warning(f"Database insert returned no data for audit entry")
                return False
                
        except Exception as e:
            logger.error(f"Failed to log audit entry to database: {e}")
            return False
    
    def _log_to_file(self, audit_entry: dict) -> bool:
        """Log audit entry to file system as backup"""
        try:
            timestamp = datetime.utcnow()
            date_str = timestamp.strftime("%Y-%m-%d")
            time_str = timestamp.strftime("%H-%M-%S")
            
            # Create daily log file
            log_file = os.path.join(self.audit_log_dir, f"sanctions_audit_{date_str}.log")
            
            # Format the log entry
            log_line = f"[{timestamp.isoformat()}] {audit_entry['action'].upper()} | {audit_entry['address']} | Partner: {audit_entry['partner_id']} | Risk: {audit_entry['risk_score']} | Factors: {', '.join(audit_entry['risk_factors'])} | Sources: {', '.join(audit_entry['data_sources'])}"
            
            if audit_entry['reason']:
                log_line += f" | Reason: {audit_entry['reason']}"
            
            # Append to log file
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(log_line + "\n")
            
            # Also create a detailed JSON log
            json_log_file = os.path.join(self.audit_log_dir, f"sanctions_audit_{date_str}.json")
            
            try:
                # Read existing logs
                if os.path.exists(json_log_file):
                    with open(json_log_file, "r", encoding="utf-8") as f:
                        existing_logs = json.load(f)
                else:
                    existing_logs = []
                
                # Add new entry
                existing_logs.append(audit_entry)
                
                # Write back to file
                with open(json_log_file, "w", encoding="utf-8") as f:
                    json.dump(existing_logs, f, indent=2, ensure_ascii=False)
                    
            except Exception as e:
                logger.error(f"Failed to write JSON audit log: {e}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to log audit entry to file: {e}")
            return False
    
    async def get_audit_logs(
        self,
        partner_id: Optional[str] = None,
        action: Optional[str] = None,
        address: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 100
    ) -> List[dict]:
        """Retrieve audit logs with optional filtering"""
        
        logs = []
        
        # Try to get from database first
        if self.supabase:
            try:
                query = self.supabase.table("sanctions_audit_log").select("*")
                
                if partner_id:
                    query = query.eq("partner_id", partner_id)
                if action:
                    query = query.eq("action", action)
                if address:
                    query = query.eq("address", address.lower())
                if start_date:
                    query = query.gte("timestamp", start_date)
                if end_date:
                    query = query.lte("timestamp", end_date)
                
                query = query.order("timestamp", desc=True).limit(limit)
                response = query.execute()
                
                if response.data:
                    logs.extend(response.data)
                    
            except Exception as e:
                logger.error(f"Failed to retrieve audit logs from database: {e}")
        
        # If no database logs or database failed, try file logs
        if not logs:
            logs = self._get_audit_logs_from_files(
                partner_id, action, address, start_date, end_date, limit
            )
        
        return logs
    
    def _get_audit_logs_from_files(
        self,
        partner_id: Optional[str] = None,
        action: Optional[str] = None,
        address: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 100
    ) -> List[dict]:
        """Retrieve audit logs from file system"""
        
        logs = []
        
        try:
            # Get all JSON log files
            if os.path.exists(self.audit_log_dir):
                for filename in os.listdir(self.audit_log_dir):
                    if filename.endswith(".json"):
                        file_path = os.path.join(self.audit_log_dir, filename)
                        
                        try:
                            with open(file_path, "r", encoding="utf-8") as f:
                                file_logs = json.load(f)
                                
                                for log_entry in file_logs:
                                    # Apply filters
                                    if partner_id and log_entry.get("partner_id") != partner_id:
                                        continue
                                    if action and log_entry.get("action") != action:
                                        continue
                                    if address and log_entry.get("address") != address.lower():
                                        continue
                                    if start_date and log_entry.get("timestamp") < start_date:
                                        continue
                                    if end_date and log_entry.get("timestamp") > end_date:
                                        continue
                                    
                                    logs.append(log_entry)
                                    
                                    if len(logs) >= limit:
                                        break
                                        
                        except Exception as e:
                            logger.error(f"Failed to read audit log file {filename}: {e}")
                            
        except Exception as e:
            logger.error(f"Failed to read audit logs from files: {e}")
        
        # Sort by timestamp (newest first) and limit results
        logs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return logs[:limit]
    
    async def get_audit_summary(self, partner_id: Optional[str] = None) -> dict:
        """Get summary statistics of audit logs"""
        
        try:
            logs = await self.get_audit_logs(partner_id=partner_id, limit=10000)
            
            if not logs:
                return {
                    "total_actions": 0,
                    "add_actions": 0,
                    "remove_actions": 0,
                    "unique_addresses": 0,
                    "average_risk_score": 0,
                    "most_common_risk_factors": [],
                    "actions_by_date": {}
                }
            
            # Calculate statistics
            total_actions = len(logs)
            add_actions = sum(1 for log in logs if log.get("action") == "add")
            remove_actions = sum(1 for log in logs if log.get("action") == "remove")
            unique_addresses = len(set(log.get("address") for log in logs))
            
            # Calculate average risk score
            risk_scores = [log.get("risk_score", 0) for log in logs if log.get("risk_score")]
            average_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0
            
            # Most common risk factors
            all_risk_factors = []
            for log in logs:
                if log.get("risk_factors"):
                    all_risk_factors.extend(log["risk_factors"])
            
            risk_factor_counts = {}
            for factor in all_risk_factors:
                risk_factor_counts[factor] = risk_factor_counts.get(factor, 0) + 1
            
            most_common_risk_factors = sorted(
                risk_factor_counts.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]
            
            # Actions by date
            actions_by_date = {}
            for log in logs:
                if log.get("timestamp"):
                    date = log["timestamp"][:10]  # YYYY-MM-DD
                    actions_by_date[date] = actions_by_date.get(date, 0) + 1
            
            return {
                "total_actions": total_actions,
                "add_actions": add_actions,
                "remove_actions": remove_actions,
                "unique_addresses": unique_addresses,
                "average_risk_score": round(average_risk_score, 2),
                "most_common_risk_factors": most_common_risk_factors,
                "actions_by_date": actions_by_date
            }
            
        except Exception as e:
            logger.error(f"Failed to generate audit summary: {e}")
            return {
                "error": str(e),
                "total_actions": 0
            }
