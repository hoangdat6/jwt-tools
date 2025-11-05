"""Job management system for async cracking tasks"""

import asyncio
import uuid
from datetime import datetime
from typing import Optional, Dict, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import threading


class JobStatus(Enum):
    """Job status enum"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Job:
    """Job data structure"""
    job_id: str
    status: JobStatus
    progress: Optional[Dict[str, Any]] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: datetime = None
    updated_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.updated_at is None:
            self.updated_at = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'job_id': self.job_id,
            'status': self.status.value,
            'progress': self.progress,
            'result': self.result,
            'error': self.error,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }


class JobManager:
    """Manage background jobs for cracking"""
    
    def __init__(self):
        self.jobs: Dict[str, Job] = {}
        self._lock = threading.Lock()
        self._subscribers: Dict[str, list] = {}  # job_id -> list of queues
    
    def create_job(self) -> str:
        """Create a new job and return job ID"""
        job_id = str(uuid.uuid4())
        
        with self._lock:
            job = Job(
                job_id=job_id,
                status=JobStatus.PENDING
            )
            self.jobs[job_id] = job
            self._subscribers[job_id] = []
        
        return job_id
    
    def get_job(self, job_id: str) -> Optional[Job]:
        """Get job by ID"""
        with self._lock:
            return self.jobs.get(job_id)
    
    def update_job(self, job_id: str, **kwargs):
        """Update job fields"""
        with self._lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            
            for key, value in kwargs.items():
                if hasattr(job, key):
                    setattr(job, key, value)
            
            job.updated_at = datetime.utcnow()
            
            # Notify subscribers
            self._notify_subscribers(job_id, job)
    
    def update_progress(self, job_id: str, progress: Dict[str, Any]):
        """Update job progress"""
        self.update_job(job_id, progress=progress, status=JobStatus.RUNNING)
    
    def complete_job(self, job_id: str, result: Dict[str, Any]):
        """Mark job as completed"""
        self.update_job(job_id, status=JobStatus.COMPLETED, result=result)
    
    def fail_job(self, job_id: str, error: str):
        """Mark job as failed"""
        self.update_job(job_id, status=JobStatus.FAILED, error=error)
    
    def cancel_job(self, job_id: str):
        """Cancel a job"""
        self.update_job(job_id, status=JobStatus.CANCELLED)
    
    def subscribe(self, job_id: str) -> asyncio.Queue:
        """Subscribe to job updates (for SSE)"""
        queue = asyncio.Queue()
        
        with self._lock:
            if job_id not in self._subscribers:
                self._subscribers[job_id] = []
            self._subscribers[job_id].append(queue)
        
        return queue
    
    def unsubscribe(self, job_id: str, queue: asyncio.Queue):
        """Unsubscribe from job updates"""
        with self._lock:
            if job_id in self._subscribers:
                try:
                    self._subscribers[job_id].remove(queue)
                except ValueError:
                    pass
    
    def _notify_subscribers(self, job_id: str, job: Job):
        """Notify all subscribers about job update"""
        if job_id not in self._subscribers:
            return
        
        job_dict = job.to_dict()
        
        for queue in self._subscribers[job_id]:
            try:
                queue.put_nowait(job_dict)
            except:
                pass
    
    def cleanup_old_jobs(self, max_age_seconds: int = 3600):
        """Clean up old completed/failed jobs"""
        now = datetime.utcnow()
        
        with self._lock:
            to_delete = []
            for job_id, job in self.jobs.items():
                if job.status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED]:
                    age = (now - job.updated_at).total_seconds()
                    if age > max_age_seconds:
                        to_delete.append(job_id)
            
            for job_id in to_delete:
                del self.jobs[job_id]
                if job_id in self._subscribers:
                    del self._subscribers[job_id]


# Global job manager instance
job_manager = JobManager()
