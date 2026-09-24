from flask import Flask, render_template, request
from src.analysis_service import AnalysisService

# Initialize the service globally so the model is only loaded once
analysis_service = AnalysisService()

app = Flask(__name__)

# Maximum allowed URL length to prevent DOS
MAX_URL_LENGTH = 2048

@app.route("/", methods=["GET", "POST"])
def index():
    error = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        
        if not url:
            error = "Please enter a URL."
        elif len(url) > MAX_URL_LENGTH:
            error = f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters."
        else:
            try:
                # Use analysis service
                analysis_result = analysis_service.analyze(url)
                
                return render_template(
                    "result.html",
                    original_url=url,
                    normalized_url=analysis_result["normalized_url"],
                    features=analysis_result["features"],
                    analysis=analysis_result
                )
            except ValueError as e:
                error = str(e)
            except Exception as e:
                error = "An unexpected error occurred during analysis."
                
    return render_template("index.html", error=error)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
