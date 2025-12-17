"""FastAPI Application"""

import asyncio
from pathlib import Path
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse
from sse_starlette.sse import EventSourceResponse

from ..parser import JWTParser
from ..verifier import JWTVerifier
from ..cracker import JWTCracker, ProgressUpdate
from ..forger import JWTForger
from .models import (
    AnalyzeRequest, AnalyzeResponse, SecurityWarningResponse, TimestampInfoResponse,
    VerifyRequest, VerifyResponse,
    CrackRequest, CrackStartResponse, JobStatusResponse,
    ForgeRequest, ForgeResponse,
    ErrorResponse
)
from .jobs import job_manager, JobStatus


def create_app() -> FastAPI:
    """Create and configure FastAPI application"""
    
    app = FastAPI(
        title="JWT Security Tool API",
        description="API for JWT token analysis, verification, and brute-force cracking",
        version="1.0.0"
    )
    
    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # In production, specify actual origins
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Serve static files (for web UI)
    static_dir = Path(__file__).parent.parent.parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    
    @app.get("/", response_class=HTMLResponse)
    async def root():
        """Serve web UI"""
        html_file = Path(__file__).parent.parent.parent / "static" / "index.html"
        if html_file.exists():
            return HTMLResponse(content=html_file.read_text(), status_code=200)
        return HTMLResponse(content="<h1>JWT Security Tool API</h1><p>API is running. Visit /docs for API documentation.</p>")
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint"""
        return {"status": "healthy"}
    
    @app.post("/api/analyze", response_model=AnalyzeResponse)
    async def analyze_token(request: AnalyzeRequest):
        """
        Parse and analyze a JWT token.
        Returns decoded header, payload, and security warnings.
        """
        try:
            parser = JWTParser()
            analysis = parser.parse(request.token)
            
            # Convert to response model
            warnings = [
                SecurityWarningResponse(
                    severity=w.severity,
                    category=w.category,
                    message=w.message,
                    recommendation=w.recommendation
                )
                for w in analysis.warnings
            ]
            
            # Convert timestamp info
            timestamp_info = {}
            for key, info in analysis.timestamp_info.items():
                timestamp_info[key] = TimestampInfoResponse(**info)
            
            return AnalyzeResponse(
                algorithm=analysis.algorithm,
                algorithm_type=analysis.algorithm_type.value,
                header=analysis.header,
                payload=analysis.payload,
                signature=analysis.signature,
                warnings=warnings,
                timestamp_info=timestamp_info
            )
            
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    
    @app.post("/api/verify", response_model=VerifyResponse)
    async def verify_signature(request: VerifyRequest):
        """
        Verify JWT signature with provided key.
        """
        try:
            verifier = JWTVerifier()
            result = verifier.verify(
                request.token,
                request.key,
                algorithm=request.algorithm
            )
            
            return VerifyResponse(
                valid=result.valid,
                algorithm=result.algorithm,
                message=result.message,
                key_info=result.key_info
            )
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")
    
    @app.post("/api/crack", response_model=CrackStartResponse)
    async def start_crack_job(request: CrackRequest, background_tasks: BackgroundTasks):
        """
        Start a brute-force cracking job.
        Returns job ID for status tracking.
        """
        try:
            # Create job
            job_id = job_manager.create_job()
            
            # Start cracking in background
            background_tasks.add_task(
                run_crack_job,
                job_id=job_id,
                token=request.token,
                wordlist=request.wordlist,
                use_common=request.use_common,
                workers=request.workers
            )
            
            return CrackStartResponse(
                job_id=job_id,
                status="pending",
                message="Cracking job started. Use /api/job/{job_id}/status to check progress."
            )
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to start crack job: {str(e)}")
    
    @app.get("/api/job/{job_id}/status", response_model=JobStatusResponse)
    async def get_job_status(job_id: str):
        """
        Get status of a cracking job.
        """
        job = job_manager.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        
        return JobStatusResponse(**job.to_dict())
    
    @app.get("/api/job/{job_id}/stream")
    async def stream_job_progress(job_id: str):
        """
        Stream real-time job progress using Server-Sent Events (SSE).
        """
        job = job_manager.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        
        async def event_generator():
            queue = job_manager.subscribe(job_id)
            
            try:
                # Send initial state
                job = job_manager.get_job(job_id)
                if job:
                    yield {
                        "event": "update",
                        "data": job.to_dict()
                    }
                
                # Stream updates
                while True:
                    try:
                        update = await asyncio.wait_for(queue.get(), timeout=30.0)
                        yield {
                            "event": "update",
                            "data": update
                        }
                        
                        # Stop if job is done
                        if update['status'] in ['completed', 'failed', 'cancelled']:
                            break
                            
                    except asyncio.TimeoutError:
                        # Send keepalive
                        yield {
                            "event": "keepalive",
                            "data": {"timestamp": asyncio.get_event_loop().time()}
                        }
                        
            finally:
                job_manager.unsubscribe(job_id, queue)
        
        return EventSourceResponse(event_generator())
    
    @app.delete("/api/job/{job_id}")
    async def cancel_job(job_id: str):
        """
        Cancel a running job.
        """
        job = job_manager.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        
        if job.status == JobStatus.RUNNING:
            job_manager.cancel_job(job_id)
            return {"message": "Job cancellation requested"}
        else:
            return {"message": f"Job is {job.status.value}, cannot cancel"}
    
    @app.post("/api/forge", response_model=ForgeResponse)
    async def forge_token(request: ForgeRequest):
        """Forge/manipulate JWT token"""
        try:
            forger = JWTForger()
            
            if request.mode == "none":
                result = forger.forge_none_algorithm(request.token, request.claims)
            elif request.mode == "modify":
                if not request.claims:
                    return ForgeResponse(success=False, message="Claims required for modify mode")
                result = forger.forge_modify_claims(request.token, request.claims, request.secret)
            elif request.mode == "confusion":
                if not request.public_key:
                    return ForgeResponse(success=False, message="Public key required for confusion mode")
                result = forger.forge_algorithm_confusion(request.token, request.public_key)
            elif request.mode == "custom":
                if not request.header or not request.payload:
                    return ForgeResponse(success=False, message="Header and payload required for custom mode")
                result = forger.forge_custom(request.header, request.payload, request.secret)
            elif request.mode == "escalate":
                escalations = forger.get_common_escalations()
                escalation_type = request.escalation_type or "user_to_admin"
                if escalation_type not in escalations:
                    return ForgeResponse(success=False, message=f"Unknown escalation type: {escalation_type}")
                escalation = escalations[escalation_type]
                result = forger.forge_modify_claims(request.token, escalation["modifications"], request.secret)
            else:
                return ForgeResponse(success=False, message=f"Unknown forge mode: {request.mode}")
            
            return ForgeResponse(
                success=result.success,
                token=result.token,
                header=result.header,
                payload=result.payload,
                attack_type=result.attack_type,
                message=result.message
            )
        except Exception as e:
            return ForgeResponse(success=False, message=f"Forge error: {str(e)}")
    
    @app.get("/api/escalations")
    async def get_escalations():
        """Get available privilege escalation scenarios"""
        forger = JWTForger()
        return forger.get_common_escalations()
    
    return app


async def run_crack_job(job_id: str, token: str, wordlist: Optional[str],
                       use_common: bool, workers: Optional[int]):
    """
    Run cracking job in background using streaming approach.
    No temp files needed - memory efficient!
    """
    try:
        job_manager.update_job(job_id, status=JobStatus.RUNNING)
        
        # Progress callback
        def progress_callback(progress: ProgressUpdate):
            progress_dict = {
                'attempts': progress.attempts,
                'elapsed_time': progress.elapsed_time,
                'attempts_per_second': progress.attempts_per_second,
                'estimated_remaining': progress.estimated_remaining,
                'percentage': progress.percentage
            }
            job_manager.update_progress(job_id, progress_dict)
        
        # Run cracker with streaming approach
        import asyncio
        loop = asyncio.get_event_loop()
        
        # Run in thread pool to avoid blocking
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as executor:
            cracker = JWTCracker(num_workers=workers)
            
            # Get all wordlist files from wordlists directory
            project_root = Path(__file__).parent.parent.parent
            wordlists_dir = project_root / "wordlists"
            
            # Combine all wordlist files
            combined_wordlist_content = ""
            if wordlists_dir.exists() and wordlists_dir.is_dir():
                # Get all .txt files in wordlists directory
                wordlist_files = sorted(wordlists_dir.glob("*.txt"))
                
                if wordlist_files:
                    print(f"Loading {len(wordlist_files)} wordlist file(s):")
                    for wl_file in wordlist_files:
                        print(f"  - {wl_file.name}")
                        try:
                            with open(wl_file, 'r', encoding='utf-8', errors='ignore') as f:
                                combined_wordlist_content += f.read() + "\n"
                        except Exception as e:
                            print(f"  Warning: Failed to load {wl_file.name}: {e}")
            
            # If user provided wordlist content, append it
            if wordlist:
                combined_wordlist_content += wordlist
            
            # Use streaming method with combined wordlist
            result = await loop.run_in_executor(
                executor,
                lambda: cracker.crack_streaming(
                    token=token,
                    wordlist_path=None,  # Use content instead of path
                    wordlist_content=combined_wordlist_content if combined_wordlist_content else None,
                    use_common=use_common,
                    progress_callback=progress_callback,
                    chunk_size=1000  # Process in chunks of 1000
                )
            )
        
        # Update job with result
        result_dict = {
            'success': result.success,
            'secret': result.secret,
            'attempts': result.attempts,
            'elapsed_time': result.elapsed_time,
            'attempts_per_second': result.attempts_per_second
        }
        
        job_manager.complete_job(job_id, result_dict)
        
    except Exception as e:
        job_manager.fail_job(job_id, str(e))


# Create app instance
app = create_app()
