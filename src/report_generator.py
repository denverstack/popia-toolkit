#!/usr/bin/env python3
"""
POPIA Report Generator
Generate compliance reports in PDF, HTML, and Markdown formats
"""

import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
import base64

# PDF generation
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    from reportlab.lib.colors import HexColor, black, red, orange, green
    from reportlab.lib.units import inch
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

logger = logging.getLogger(__name__)

class POPIAReportGenerator:
    """Generate POPIA compliance reports in multiple formats"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet() if REPORTLAB_AVAILABLE else None
        self.colors = {
            'HIGH': HexColor('#dc3545') if REPORTLAB_AVAILABLE else '#dc3545',
            'MEDIUM': HexColor('#fd7e14') if REPORTLAB_AVAILABLE else '#fd7e14',
            'LOW': HexColor('#28a745') if REPORTLAB_AVAILABLE else '#28a745'
        }
    
    def generate_report(self, scan_data: Dict[str, Any], validation_data: Dict[str, Any] = None, 
                       output_format: str = 'html', output_path: str = None) -> str:
        """Generate compliance report in specified format"""
        
        if output_format.lower() == 'pdf':
            return self._generate_pdf_report(scan_data, validation_data, output_path)
        elif output_format.lower() == 'html':
            return self._generate_html_report(scan_data, validation_data, output_path)
        elif output_format.lower() == 'md' or output_format.lower() == 'markdown':
            return self._generate_markdown_report(scan_data, validation_data, output_path)
        else:
            raise ValueError(f"Unsupported format: {output_format}")
    
    def _generate_pdf_report(self, scan_data: Dict[str, Any], validation_data: Dict[str, Any], 
                            output_path: str) -> str:
        """Generate PDF compliance report"""
        
        if not REPORTLAB_AVAILABLE:
            raise ImportError("ReportLab is required for PDF generation. Install with: pip install reportlab")
        
        if not output_path:
            output_path = f"popia_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        # Create PDF document
        doc = SimpleDocTemplate(output_path, pagesize=A4, rightMargin=72, leftMargin=72,
                               topMargin=72, bottomMargin=18)
        
        # Build story (content)
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=HexColor('#2c3e50')
        )
        story.append(Paragraph("POPIA Compliance Report", title_style))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.styles['Heading2']))
        
        total_matches = scan_data.get('total_matches', 0)
        severity_breakdown = scan_data.get('severity_breakdown', {})
        compliance_status = validation_data.get('compliance_status', 'UNKNOWN') if validation_data else 'NO_VALIDATION'
        
        summary_text = f"""
        <b>Scan Date:</b> {scan_data.get('scan_timestamp', 'Unknown')}<br/>
        <b>Total PII Findings:</b> {total_matches}<br/>
        <b>Compliance Status:</b> <font color="{self.colors['HIGH'] if compliance_status == 'FAIL' else 'green'}">{compliance_status}</font><br/>
        <b>High Severity:</b> {severity_breakdown.get('HIGH', 0)}<br/>
        <b>Medium Severity:</b> {severity_breakdown.get('MEDIUM', 0)}<br/>
        <b>Low Severity:</b> {severity_breakdown.get('LOW', 0)}
        """
        
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # POPIA Sections Affected
        affected_sections = scan_data.get('popia_sections_affected', [])
        if affected_sections:
            story.append(Paragraph("POPIA Sections Affected", self.styles['Heading2']))
            for section in affected_sections:
                story.append(Paragraph(f"• {section}", self.styles['Normal']))
            story.append(Spacer(1, 20))
        
        # Policy Violations (if available)
        if validation_data and validation_data.get('violations'):
            story.append(Paragraph("Policy Violations", self.styles['Heading2']))
            
            violations_data = [['Rule', 'Message', 'Severity', 'File']]
            for violation in validation_data['violations']:
                violations_data.append([
                    violation.get('rule', ''),
                    violation.get('message', '')[:50] + '...' if len(violation.get('message', '')) > 50 else violation.get('message', ''),
                    violation.get('severity', ''),
                    violation.get('file_path', '')[:30] + '...' if len(violation.get('file_path', '')) > 30 else violation.get('file_path', '')
                ])
            
            violations_table = Table(violations_data)
            violations_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#f8f9fa')),
                ('TEXTCOLOR', (0, 0), (-1, 0), black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ffffff')),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#dddddd'))
            ]))
            
            story.append(violations_table)
            story.append(PageBreak())
        
        # Detailed Findings
        story.append(Paragraph("Detailed Findings", self.styles['Heading2']))
        
        if scan_data.get('matches'):
            # Group by severity
            findings_by_severity = {'HIGH': [], 'MEDIUM': [], 'LOW': []}
            for match in scan_data['matches']:
                severity = match.get('severity', 'LOW')
                findings_by_severity[severity].append(match)
            
            for severity in ['HIGH', 'MEDIUM', 'LOW']:
                if findings_by_severity[severity]:
                    story.append(Paragraph(f"{severity} Severity Findings ({len(findings_by_severity[severity])})", 
                                         self.styles['Heading3']))
                    
                    findings_data = [['Type', 'File', 'Line', 'Context']]
                    for match in findings_by_severity[severity][:10]:  # Limit to first 10
                        findings_data.append([
                            match.get('type', ''),
                            match.get('file_path', '')[:25] + '...' if len(match.get('file_path', '')) > 25 else match.get('file_path', ''),
                            str(match.get('line_number', '')),
                            match.get('context', '')[:40] + '...' if len(match.get('context', '')) > 40 else match.get('context', '')
                        ])
                    
                    findings_table = Table(findings_data)
                    findings_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), self.colors[severity]),
                        ('TEXTCOLOR', (0, 0), (-1, 0), black),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ffffff')),
                        ('FONTSIZE', (0, 1), (-1, -1), 7),
                        ('GRID', (0, 0), (-1, -1), 1, HexColor('#dddddd'))
                    ]))
                    
                    story.append(findings_table)
                    story.append(Spacer(1, 15))
        
        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Recommendations", self.styles['Heading2']))
        
        recommendations = self._generate_recommendations(scan_data, validation_data)
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['Normal']))
        
        # Build PDF
        doc.build(story)
        logger.info(f"PDF report generated: {output_path}")
        
        return output_path
    
    def _generate_html_report(self, scan_data: Dict[str, Any], validation_data: Dict[str, Any], 
                             output_path: str) -> str:
        """Generate HTML compliance report"""
        
        if not output_path:
            output_path = f"popia_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        total_matches = scan_data.get('total_matches', 0)
        severity_breakdown = scan_data.get('severity_breakdown', {})
        compliance_status = validation_data.get('compliance_status', 'UNKNOWN') if validation_data else 'NO_VALIDATION'
        
        # Generate HTML content
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>POPIA Compliance Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(45deg, #2c3e50, #34495e);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            margin: 0;
            font-size: 2.5rem;
            font-weight: 300;
        }}
        
        .header .subtitle {{
            margin-top: 10px;
            font-size: 1.1rem;
            opacity: 0.8;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .summary-card {{
            background: #f8f9fa;
            border-radius: 10px;
            padding: 25px;
            text-align: center;
            border-left: 4px solid #007bff;
        }}
        
        .summary-card.high {{ border-left-color: #dc3545; }}
        .summary-card.medium {{ border-left-color: #fd7e14; }}
        .summary-card.low {{ border-left-color: #28a745; }}
        .summary-card.status {{ border-left-color: #6f42c1; }}
        
        .summary-card h3 {{
            margin: 0 0 10px 0;
            font-size: 2rem;
            font-weight: bold;
        }}
        
        .summary-card p {{
            margin: 0;
            color: #6c757d;
            font-size: 0.9rem;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section h2 {{
            color: #2c3e50;
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        
        .table-container {{
            overflow-x: auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #e9ecef;
        }}
        
        th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }}
        
        .severity-high {{ color: #dc3545; font-weight: bold; }}
        .severity-medium {{ color: #fd7e14; font-weight: bold; }}
        .severity-low {{ color: #28a745; font-weight: bold; }}
        
        .status-pass {{ color: #28a745; font-weight: bold; }}
        .status-fail {{ color: #dc3545; font-weight: bold; }}
        
        .recommendations {{
            background: #e7f3ff;
            border-radius: 8px;
            padding: 20px;
            margin-top: 30px;
        }}
        
        .recommendations h3 {{
            color: #0056b3;
            margin-top: 0;
        }}
        
        .recommendations ul {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        
        .recommendations li {{
            margin: 8px 0;
            line-height: 1.5;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #6c757d;
            font-size: 0.9rem;
        }}
        
        .chart-container {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>POPIA Compliance Report</h1>
            <div class="subtitle">Generated on {datetime.now().strftime('%B %d, %Y at %H:%M')}</div>
        </div>
        
        <div class="content">
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>{total_matches}</h3>
                    <p>Total PII Findings</p>
                </div>
                <div class="summary-card high">
                    <h3>{severity_breakdown.get('HIGH', 0)}</h3>
                    <p>High Severity</p>
                </div>
                <div class="summary-card medium">
                    <h3>{severity_breakdown.get('MEDIUM', 0)}</h3>
                    <p>Medium Severity</p>
                </div>
                <div class="summary-card low">
                    <h3>{severity_breakdown.get('LOW', 0)}</h3>
                    <p>Low Severity</p>
                </div>
                <div class="summary-card status">
                    <h3 class="status-{'pass' if compliance_status == 'PASS' else 'fail'}">{compliance_status}</h3>
                    <p>Compliance Status</p>
                </div>
            </div>
        """
        
        # Add POPIA sections
        affected_sections = scan_data.get('popia_sections_affected', [])
        if affected_sections:
            html_content += f"""
            <div class="section">
                <h2>POPIA Sections Affected</h2>
                <ul>
                    {''.join(f'<li>{section}</li>' for section in affected_sections)}
                </ul>
            </div>
            """
        
        # Add policy violations
        if validation_data and validation_data.get('violations'):
            html_content += f"""
            <div class="section">
                <h2>Policy Violations ({len(validation_data['violations'])})</h2>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Rule</th>
                                <th>Message</th>
                                <th>Severity</th>
                                <th>File</th>
                            </tr>
                        </thead>
                        <tbody>
            """
            
            for violation in validation_data['violations']:
                severity_class = f"severity-{violation.get('severity', 'low').lower()}"
                html_content += f"""
                            <tr>
                                <td><code>{violation.get('rule', '')}</code></td>
                                <td>{violation.get('message', '')}</td>
                                <td class="{severity_class}">{violation.get('severity', '')}</td>
                                <td><code>{violation.get('file_path', '')}</code></td>
                            </tr>
                """
            
            html_content += """
                        </tbody>
                    </table>
                </div>
            </div>
            """
        
        # Add detailed findings
        if scan_data.get('matches'):
            html_content += """
            <div class="section">
                <h2>Detailed Findings</h2>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>File</th>
                                <th>Line</th>
                                <th>Severity</th>
                                <th>Context</th>
                                <th>POPIA Section</th>
                            </tr>
                        </thead>
                        <tbody>
            """
            
            # Show first 50 matches
            for match in scan_data['matches'][:50]:
                severity = match.get('severity', 'LOW')
                severity_class = f"severity-{severity.lower()}"
                context = match.get('context', '')[:60] + '...' if len(match.get('context', '')) > 60 else match.get('context', '')
                
                html_content += f"""
                            <tr>
                                <td><strong>{match.get('type', '')}</strong></td>
                                <td><code>{match.get('file_path', '')}</code></td>
                                <td>{match.get('line_number', '')}</td>
                                <td class="{severity_class}">{severity}</td>
                                <td><em>{context}</em></td>
                                <td>{match.get('popia_section', '')[:30]}...</td>
                            </tr>
                """
            
            if len(scan_data['matches']) > 50:
                html_content += f"""
                            <tr>
                                <td colspan="6" style="text-align: center; font-style: italic; color: #6c757d;">
                                    ... and {len(scan_data['matches']) - 50} more findings
                                </td>
                            </tr>
                """
            
            html_content += """
                        </tbody>
                    </table>
                </div>
            </div>
            """
        
        # Add recommendations
        recommendations = self._generate_recommendations(scan_data, validation_data)
        html_content += f"""
            <div class="recommendations">
                <h3>🔍 Recommendations</h3>
                <ul>
                    {''.join(f'<li>{rec}</li>' for rec in recommendations)}
                </ul>
            </div>
        """
        
        # Close HTML
        html_content += """
        </div>
        
        <div class="footer">
            <p>Generated by POPIA Privacy-as-Code Toolkit | For internal use only</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {output_path}")
        return output_path
    
    def _generate_markdown_report(self, scan_data: Dict[str, Any], validation_data: Dict[str, Any], 
                                 output_path: str) -> str:
        """Generate Markdown compliance report"""
        
        if not output_path:
            output_path = f"popia_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        total_matches = scan_data.get('total_matches', 0)
        severity_breakdown = scan_data.get('severity_breakdown', {})
        compliance_status = validation_data.get('compliance_status', 'UNKNOWN') if validation_data else 'NO_VALIDATION'
        
        # Generate Markdown content
        md_content = f"""# POPIA Compliance Report

**Generated:** {datetime.now().strftime('%B %d, %Y at %H:%M')}

## Executive Summary

| Metric | Value |
|--------|-------|
| **Total PII Findings** | {total_matches} |
| **Compliance Status** | {compliance_status} |
| **High Severity** | {severity_breakdown.get('HIGH', 0)} |
| **Medium Severity** | {severity_breakdown.get('MEDIUM', 0)} |
| **Low Severity** | {severity_breakdown.get('LOW', 0)} |

"""
        
        # Add POPIA sections
        affected_sections = scan_data.get('popia_sections_affected', [])
        if affected_sections:
            md_content += "## POPIA Sections Affected\n\n"
            for section in affected_sections:
                md_content += f"- {section}\n"
            md_content += "\n"
        
        # Add policy violations
        if validation_data and validation_data.get('violations'):
            md_content += f"## Policy Violations ({len(validation_data['violations'])})\n\n"
            md_content += "| Rule | Message | Severity | File |\n"
            md_content += "|------|---------|----------|------|\n"
            
            for violation in validation_data['violations']:
                rule = violation.get('rule', '')
                message = violation.get('message', '').replace('|', '\\|')
                severity = violation.get('severity', '')
                file_path = violation.get('file_path', '').replace('|', '\\|')
                md_content += f"| `{rule}` | {message} | {severity} | `{file_path}` |\n"
            
            md_content += "\n"
        
        # Add detailed findings
        if scan_data.get('matches'):
            md_content += "## Detailed Findings\n\n"
            
            # Group by severity
            findings_by_severity = {'HIGH': [], 'MEDIUM': [], 'LOW': []}
            for match in scan_data['matches']:
                severity = match.get('severity', 'LOW')
                findings_by_severity[severity].append(match)
            
            for severity in ['HIGH', 'MEDIUM', 'LOW']:
                if findings_by_severity[severity]:
                    md_content += f"### {severity} Severity Findings ({len(findings_by_severity[severity])})\n\n"
                    md_content += "| Type | File | Line | Context | POPIA Section |\n"
                    md_content += "|------|------|------|---------|---------------|\n"
                    
                    # Show first 20 findings per severity
                    for match in findings_by_severity[severity][:20]:
                        pii_type = match.get('type', '')
                        file_path = match.get('file_path', '').replace('|', '\\|')
                        line_num = match.get('line_number', '')
                        context = match.get('context', '').replace('|', '\\|')[:50]
                        if len(match.get('context', '')) > 50:
                            context += '...'
                        popia_section = match.get('popia_section', '').replace('|', '\\|')[:30]
                        if len(match.get('popia_section', '')) > 30:
                            popia_section += '...'
                        
                        md_content += f"| **{pii_type}** | `{file_path}` | {line_num} | _{context}_ | {popia_section} |\n"
                    
                    if len(findings_by_severity[severity]) > 20:
                        md_content += f"| ... | ... | ... | ... | _{len(findings_by_severity[severity]) - 20} more findings_ |\n"
                    
                    md_content += "\n"
        
        # Add recommendations
        recommendations = self._generate_recommendations(scan_data, validation_data)
        md_content += "## 🔍 Recommendations\n\n"
        for rec in recommendations:
            md_content += f"- {rec}\n"
        
        md_content += f"""

---

**Report generated by POPIA Privacy-as-Code Toolkit**  
*For internal use only*
"""
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        logger.info(f"Markdown report generated: {output_path}")
        return output_path
    
    def _generate_recommendations(self, scan_data: Dict[str, Any], validation_data: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on scan results"""
        recommendations = []
        
        total_matches = scan_data.get('total_matches', 0)
        severity_breakdown = scan_data.get('severity_breakdown', {})
        
        if total_matches == 0:
            recommendations.append("✅ No PII detected. Continue monitoring with regular scans.")
            return recommendations
        
        # High severity recommendations
        if severity_breakdown.get('HIGH', 0) > 0:
            recommendations.append("🚨 **HIGH PRIORITY**: Remove or encrypt high-severity PII findings immediately")
            recommendations.append("🔐 Implement data encryption for files containing sensitive information")
            recommendations.append("🚫 Add ignore rules for test fixtures containing synthetic data")
        
        # Medium severity recommendations  
        if severity_breakdown.get('MEDIUM', 0) > 5:
            recommendations.append("⚠️ Consider implementing data masking for medium-severity findings")
            recommendations.append("📋 Review data retention policies for personal information")
        
        # Policy violation recommendations
        if validation_data and validation_data.get('violations'):
            recommendations.append("📜 **POLICY VIOLATIONS**: Address policy violations before deployment")
            recommendations.append("🔧 Update CI/CD pipeline to enforce POPIA compliance checks")
        
        # General recommendations
        recommendations.extend([
            "📚 Train development team on POPIA compliance best practices",
            "🔄 Schedule regular automated PII scans in CI/CD pipeline",
            "📊 Implement data classification system for sensitive files",
            "🗂️ Maintain inventory of personal information processing activities",
            "🔍 Review and update ignore patterns for legitimate test data"
        ])
        
        return recommendations[:8]  # Limit to top 8 recommendations

def main():
    """CLI for report generation"""
    import argparse
    
    parser = argparse.ArgumentParser(description='POPIA Report Generator')
    parser.add_argument('--input', required=True, help='Scan results JSON file')
    parser.add_argument('--validation', help='Policy validation results JSON file')
    parser.add_argument('--format', choices=['pdf', 'html', 'md', 'markdown'], 
                       default='html', help='Report format')
    parser.add_argument('--output', help='Output file path')
    
    args = parser.parse_args()
    
    # Load scan results
    try:
        with open(args.input, 'r') as f:
            scan_data = json.load(f)
    except Exception as e:
        logger.error(f"Error loading scan results: {str(e)}")
        return 1
    
    # Load validation results (optional)
    validation_data = None
    if args.validation:
        try:
            with open(args.validation, 'r') as f:
                validation_data = json.load(f)
        except Exception as e:
            logger.warning(f"Error loading validation results: {str(e)}")
    
    # Generate report
    try:
        generator = POPIAReportGenerator()
        output_path = generator.generate_report(scan_data, validation_data, args.format, args.output)
        print(f"Report generated successfully: {output_path}")
        return 0
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return 1

if __name__ == '__main__':
    exit(main())