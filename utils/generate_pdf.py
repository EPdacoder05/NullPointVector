import os
import sys
import markdown
import weasyprint
import jinja2
import logging
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pdf_generation.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class PDFGenerator:
    def __init__(self):
        self.docs_dir = Path('docs')
        self.template_dir = Path('templates')
        self.output_dir = Path('docs')
        self.setup_directories()

    def setup_directories(self):
        """Create necessary directories if they don't exist."""
        self.docs_dir.mkdir(exist_ok=True)
        self.template_dir.mkdir(exist_ok=True)
        self.output_dir.mkdir(exist_ok=True)

    def create_css_file(self):
        """Create CSS file for PDF styling."""
        css_content = """
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 2cm;
            color: #333;
        }
        h1, h2, h3, h4, h5, h6 {
            color: #2c3e50;
            margin-top: 1.5em;
            margin-bottom: 0.5em;
        }
        h1 { font-size: 24pt; }
        h2 { font-size: 20pt; }
        h3 { font-size: 16pt; }
        code {
            background-color: #f8f9fa;
            padding: 0.2em 0.4em;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        pre {
            background-color: #f8f9fa;
            padding: 1em;
            border-radius: 5px;
            overflow-x: auto;
        }
        pre code {
            background-color: transparent;
            padding: 0;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin: 1em 0;
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
        .footer {
            text-align: center;
            font-size: 10pt;
            color: #666;
            margin-top: 2em;
            border-top: 1px solid #ddd;
            padding-top: 1em;
        }
        """
        css_file = self.template_dir / 'style.css'
        css_file.write_text(css_content)
        return css_file

    def generate_pdf(self, markdown_file, output_file):
        """Generate PDF from markdown file."""
        try:
            # Read markdown content
            markdown_path = self.docs_dir / markdown_file
            if not markdown_path.exists():
                raise FileNotFoundError(f"Markdown file not found: {markdown_path}")

            content = markdown_path.read_text()

            # Convert markdown to HTML
            html_content = markdown.markdown(
                content,
                extensions=['extra', 'codehilite', 'tables', 'fenced_code']
            )

            # Create HTML template
            template = """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Technical Journey</title>
                <link rel="stylesheet" href="style.css">
            </head>
            <body>
                {{ content }}
                <div class="footer">
                    Generated on: {{ generated_date }}
                </div>
            </body>
            </html>
            """

            # Render template
            template = jinja2.Template(template)
            html = template.render(
                content=html_content,
                generated_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            )

            # Create CSS file
            css_file = self.create_css_file()

            # Generate PDF
            output_path = self.output_dir / output_file
            weasyprint.HTML(string=html).write_pdf(
                output_path,
                stylesheets=[str(css_file)]
            )

            logging.info(f"Successfully generated PDF: {output_path}")
            return True

        except Exception as e:
            logging.error(f"Error generating PDF: {str(e)}")
            return False

def main():
    generator = PDFGenerator()
    success = generator.generate_pdf(
        'TECHNICAL_JOURNEY.md',
        'TECHNICAL_JOURNEY.pdf'
    )
    if success:
        print("PDF generation completed successfully!")
    else:
        print("PDF generation failed. Check pdf_generation.log for details.")

if __name__ == '__main__':
    main() 