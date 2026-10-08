import time
import uuid
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Enterprise Mock AI Backend", version="1.0.0")

# Available Models in the Lab
VALID_MODELS = {
    "dev-code-llm": "Engineering & Development Model (Code Generation, Refactoring, Debugging)",
    "financial-analyzer-llm": "Finance & Accounting Model (Forecasting, P&L Analysis, Valuation)",
    "hr-assistant-llm": "HR & People Ops Model (Job Descriptions, Policy FAQs, Interview Prep)"
}

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = 512
    stream: Optional[bool] = False
    user: Optional[str] = "default-user"

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "mock-ai-backend", "models": list(VALID_MODELS.keys())}

@app.get("/v1/models")
def list_models():
    return {
        "object": "list",
        "data": [
            {
                "id": model_id,
                "object": "model",
                "created": 1700000000,
                "owned_by": "lab-internal-ai-service",
                "description": desc
            }
            for model_id, desc in VALID_MODELS.items()
        ]
    }

@app.post("/v1/chat/completions")
def create_chat_completion(request: ChatCompletionRequest):
    if request.model not in VALID_MODELS:
        raise HTTPException(
            status_code=404,
            detail=f"Model '{request.model}' not found. Supported models: {list(VALID_MODELS.keys())}"
        )
    
    # Calculate approximate tokens for input
    combined_prompt = " ".join([m.content for m in request.messages])
    # Approximate rule-of-thumb: 1 token ~ 4 characters
    prompt_tokens = max(1, len(combined_prompt) // 4)
    
    # Generate domain-specific mock response
    if request.model == "dev-code-llm":
        content = (
            "```python\n# Enterprise Code Assistant Response\ndef process_data(records):\n"
            "    \"\"\"Sanitized data processor with audit logging.\"\"\"\n"
            "    return [r.strip().lower() for r in records if r]\n```\n"
            "Code compiled and validated against corporate security standards."
        )
    elif request.model == "financial-analyzer-llm":
        content = (
            "**Financial Analysis Summary**:\n"
            "- Q3 Operating Margin: 24.8% (Target: 22.0%)\n"
            "- Projected Runway: 18.5 months based on current burn rate.\n"
            "- Confidence Interval: 94.2% across Monte Carlo simulations."
        )
    elif request.model == "hr-assistant-llm":
        content = (
            "**People Ops & Policy Advisory**:\n"
            "Under the Hybrid Working Policy (Section 4.2), employees may request up to "
            "two remote days per week with line manager approval. Standard core collaboration "
            "hours are 10:00 to 16:00."
        )
    else:
        content = f"Standard response generated for model {request.model}."

    completion_tokens = max(1, len(content) // 4)
    total_tokens = prompt_tokens + completion_tokens

    response_payload = {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": request.model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": content
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens
        }
    }
    return response_payload

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
