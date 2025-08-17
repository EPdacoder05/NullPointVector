import os
import sys
from pathlib import Path
import markdown
from weasyprint import HTML, CSS
from jinja2 import Template
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def generate_pdf():
    """Generate PDF documentation from Markdown files."""
    try:
        # Create docs directory if it doesn't exist
        docs_dir = Path('docs')
        docs_dir.mkdir(exist_ok=True)
        
        # Read the technical journey markdown
        with open(docs_dir / 'TECHNICAL_JOURNEY.md', 'r') as f:
            content = f.read()
        
        # Convert markdown to HTML
        html_content = markdown.markdown(
            content,
            extensions=['extra', 'codehilite']
        )
        
        # Create HTML template
        template = Template("""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>From Yahoo_Phish to NullPointVector: A Technical Journey</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    margin: 2cm;
                }
                h1 {
                    color: #2c3e50;
                    border-bottom: 2px solid #3498db;
                    padding-bottom: 10px;
                }
                h2 {
                    color: #34495e;
                    margin-top: 30px;
                }
                h3 {
                    color: #7f8c8d;
                }
                code {
                    background-color: #f8f9fa;
                    padding: 2px 4px;
                    border-radius: 4px;
                    font-family: 'Courier New', monospace;
                }
                pre {
                    background-color: #f8f9fa;
                    padding: 15px;
                    border-radius: 4px;
                    overflow-x: auto;
                }
                table {
                    border-collapse: collapse;
                    width: 100%;
                    margin: 20px 0;
                }
                th, td {
                    border: 1px solid #ddd;
                    padding: 8px;
                    text-align: left;
                }
                th {
                    background-color: #f8f9fa;
                }
                img {
                    max-width: 100%;
                    height: auto;
                }
                .page-break {
                    page-break-after: always;
                }
            </style>
        </head>
        <body>
            {{ content }}
        </body>
        </html>
        """)
        
        # Render HTML
        html = template.render(content=html_content)
        
        # Generate PDF
        pdf_path = docs_dir / 'TECHNICAL_JOURNEY.pdf'
        HTML(string=html).write_pdf(pdf_path)
        
        logger.info(f"PDF generated successfully at {pdf_path}")
        return True
        
    except Exception as e:
        logger.error(f"Error generating PDF: {e}", exc_info=True)
        return False

if __name__ == "__main__":
    generate_pdf() 