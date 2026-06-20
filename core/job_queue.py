"""
Background Job Queue

Allows long-running scans/attacks to run asynchronously with status tracking.
"""

import uuid
import time
import threading
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, Future


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Job:
    """Represents a background job"""
    id: str
    name: str
    target: str
    status: JobStatus = JobStatus.PENDING
    progress: int = 0
    total_steps: int = 100
    result: Any = None
    error: str = None
    created_at: float = field(default_factory=time.time)
    started_at: float = None
    completed_at: float = None
    logs: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    _cancel_flag: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for API response"""
        with self._lock:
            return {
                "id": self.id,
                "name": self.name,
                "target": self.target,
                "status": self.status.value,
                "progress": self.progress,
                "total_steps": self.total_steps,
                "progress_percent": round(self.progress / max(self.total_steps, 1) * 100, 1),
                "result": self.result,
                "error": self.error,
                "created_at": datetime.fromtimestamp(self.created_at).isoformat() + "Z",
                "started_at": datetime.fromtimestamp(self.started_at).isoformat() + "Z" if self.started_at else None,
                "completed_at": datetime.fromtimestamp(self.completed_at).isoformat() + "Z" if self.completed_at else None,
                "duration_seconds": round(self.completed_at - self.started_at, 2) if self.completed_at and self.started_at else None,
                "logs": self.logs[-50:],  # Last 50 logs
                "metadata": self.metadata
            }
    
    def update_progress(self, progress: int, log_message: str = None):
        """Update job progress"""
        with self._lock:
            self.progress = min(progress, self.total_steps)
            if log_message:
                self.logs.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] {log_message}")
    
    def add_log(self, message: str):
        """Add log message"""
        with self._lock:
            self.logs.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] {message}")
    
    def is_cancelled(self) -> bool:
        """Check if job was cancelled"""
        return self._cancel_flag
    
    def cancel(self):
        """Mark job for cancellation"""
        self._cancel_flag = True


class JobQueue:
    """
    Background job queue with status tracking and cancellation support.
    
    Usage:
        queue = JobQueue(max_workers=4)
        
        def my_scan(job: Job, url: str):
            for i in range(10):
                if job.is_cancelled():
                    return {"cancelled": True}
                job.update_progress(i * 10, f"Step {i}")
                time.sleep(1)
            return {"findings": [...]}
        
        job_id = queue.submit("scan", "https://example.com", my_scan, "https://example.com")
        
        # Check status
        status = queue.get_status(job_id)
        
        # Cancel if needed
        queue.cancel(job_id)
    """
    
    def __init__(self, max_workers: int = 4, max_jobs: int = 1000):
        """
        Args:
            max_workers: Maximum concurrent jobs
            max_jobs: Maximum jobs to keep in history
        """
        self.max_workers = max_workers
        self.max_jobs = max_jobs
        
        self._jobs: Dict[str, Job] = {}
        self._futures: Dict[str, Future] = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="job_")
    
    def submit(
        self,
        name: str,
        target: str,
        func: Callable,
        *args,
        total_steps: int = 100,
        metadata: Dict = None,
        **kwargs
    ) -> str:
        """
        Submit a job for background execution.
        
        Args:
            name: Job name/type (e.g., "nmap_scan", "subdomain_enum")
            target: Target being scanned
            func: Function to execute. First argument will be the Job object.
            *args: Additional arguments for func
            total_steps: Total steps for progress tracking
            metadata: Additional metadata to store
            **kwargs: Additional keyword arguments for func
        
        Returns:
            Job ID
        """
        job_id = str(uuid.uuid4())[:12]
        
        job = Job(
            id=job_id,
            name=name,
            target=target,
            total_steps=total_steps,
            metadata=metadata or {}
        )
        
        with self._lock:
            # Cleanup old jobs if at capacity
            self._cleanup_old_jobs()
            self._jobs[job_id] = job
        
        # Submit to executor
        future = self._executor.submit(self._run_job, job, func, args, kwargs)
        
        with self._lock:
            self._futures[job_id] = future
        
        return job_id
    
    def _run_job(self, job: Job, func: Callable, args: tuple, kwargs: dict):
        """Execute job and handle result/errors"""
        with job._lock:
            job.status = JobStatus.RUNNING
            job.started_at = time.time()
        job.add_log(f"Job started: {job.name}")
        
        try:
            # Call function with job as first argument
            result = func(job, *args, **kwargs)
            
            if job.is_cancelled():
                with job._lock:
                    job.status = JobStatus.CANCELLED
                job.add_log("Job cancelled")
            else:
                with job._lock:
                    job.status = JobStatus.COMPLETED
                    job.result = result
                    job.progress = job.total_steps
                job.add_log("Job completed successfully")
        except Exception as e:
            with job._lock:
                job.status = JobStatus.FAILED
                job.error = str(e)
            job.add_log(f"Job failed: {e}")
        finally:
            with job._lock:
                job.completed_at = time.time()
    
    def get_status(self, job_id: str) -> Optional[Dict]:
        """Get job status"""
        with self._lock:
            job = self._jobs.get(job_id)
            if job:
                return job.to_dict()
            return None
    
    def get_job(self, job_id: str) -> Optional[Job]:
        """Get job object (for internal use)"""
        with self._lock:
            return self._jobs.get(job_id)
    
    def cancel(self, job_id: str) -> bool:
        """
        Request job cancellation.
        Note: Job must check is_cancelled() to actually stop.
        
        Returns:
            True if job found and cancellation requested
        """
        with self._lock:
            job = self._jobs.get(job_id)
            if job and job.status in (JobStatus.PENDING, JobStatus.RUNNING):
                job.cancel()
                job.add_log("Cancellation requested")
                return True
            return False
    
    def list_jobs(
        self,
        target: str = None,
        status: JobStatus = None,
        limit: int = 50
    ) -> List[Dict]:
        """List jobs with optional filtering"""
        with self._lock:
            jobs = list(self._jobs.values())
        
        # Filter
        if target:
            jobs = [j for j in jobs if j.target == target]
        if status:
            jobs = [j for j in jobs if j.status == status]
        
        # Sort by created_at descending
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        
        return [j.to_dict() for j in jobs[:limit]]
    
    def _cleanup_old_jobs(self):
        """Remove old completed/failed jobs if at capacity"""
        if len(self._jobs) < self.max_jobs:
            return
        
        # Get completed/failed jobs sorted by completed_at
        removable = []
        for job_id, job in self._jobs.items():
            if job.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
                with job._lock:
                    completed_at = job.completed_at
                removable.append((job_id, completed_at or 0))
        removable.sort(key=lambda x: x[1])
        
        # Remove oldest 10%
        to_remove = max(1, len(removable) // 10)
        for job_id, _ in removable[:to_remove]:
            self._jobs.pop(job_id, None)
            self._futures.pop(job_id, None)
    
    def get_stats(self) -> Dict:
        """Get queue statistics"""
        with self._lock:
            by_status = {}
            for job in self._jobs.values():
                status = job.status.value
                by_status[status] = by_status.get(status, 0) + 1
            
            return {
                "total_jobs": len(self._jobs),
                "by_status": by_status,
                "max_workers": self.max_workers,
                "active_workers": len([f for f in self._futures.values() if not f.done()])
            }
    
    def shutdown(self, wait: bool = True):
        """Shutdown the job queue"""
        self._executor.shutdown(wait=wait)


# Global job queue instance
_global_queue: Optional[JobQueue] = None
_queue_lock = threading.Lock()


def get_job_queue() -> JobQueue:
    """Get global job queue instance"""
    global _global_queue
    with _queue_lock:
        if _global_queue is None:
            _global_queue = JobQueue()
        return _global_queue


def submit_job(
    name: str,
    target: str,
    func: Callable,
    *args,
    **kwargs
) -> str:
    """Submit job to global queue"""
    return get_job_queue().submit(name, target, func, *args, **kwargs)


def get_job_status(job_id: str) -> Optional[Dict]:
    """Get job status from global queue"""
    return get_job_queue().get_status(job_id)


def cancel_job(job_id: str) -> bool:
    """Cancel job in global queue"""
    return get_job_queue().cancel(job_id)
