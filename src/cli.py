#!/usr/bin/env python3
"""
POPIA Privacy-as-Code CLI
Main command-line interface for the POPIA toolkit
"""

import argparse
import sys
import json
import logging
import tempfile
import subprocess
import yaml
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import our modules (assuming they're in the same package)
try:
    from popia_scanner import POPIAScanner
    from popia_policy_engine import POPIAPolicyEngine
    from popia_report_generator import POPIAReportGenerator
except ImportError:
    # Handle case where modules aren't packaged yet
    logger.warning("Modules not found as package. Ensure popia_scanner.py, popia_policy_engine.py, and popia_report_generator.py are in the same directory.")
    sys.exit(1)

class POPIAConfig:
    """Configuration management for POPIA toolkit"""
    
    DEFAULT_CONFIG = {
        'scan': {
            'extensions': ['.py', '.js', '.ts', '.java', '.cpp', '.c', '.txt', '.md', '.json', '.xml', '.csv'],
            'ignore_patterns': [
                r'.*/__pycache__/.*',
                r'.*/\.git/.*',
                r'.*/node_modules/.*',
                r'.*\.pyc,
                r'.*\.log
            ]
        },
        'policies': {
            'enabled': True,
            'custom_policy_dir': None,
            'severity_limits': {
                'HIGH': 0,
                'MEDIUM': 10,
                'LOW': 50
            }
        },
        'reporting': {
            'default_format': 'html',
            'include_context': True,
            'max_findings_per_severity': 50
        }
    }
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self.DEFAULT_CONFIG.copy()
        if config_path and Path(config_path).exists():
            self.load_config(config_path)
    
    def load_config(self, config_path: str):
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                self._merge_config(self.config, user_config)
            logger.info(f"Loaded configuration from {config_path}")
        except Exception as e:
            logger.error(f"Error loading config: {str(e)}")
    
    def _merge_config(self, default: Dict, user: Dict):
        """Recursively merge user config with defaults"""
        for key, value in user.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self._merge_config(default[key], value)
            else:
                default[key] = value
    
    def create_default_config(self, output_path: str):
        """Create default configuration file"""
        with open(output_path, 'w') as f:
            yaml.dump(self.DEFAULT_CONFIG, f, default_flow_style=False, indent=2)
        logger.info(f"Created default configuration: {output_path}")

class POPIACli:
    """Main CLI application"""
    
    def __init__(self):
        self.config = None
        self.scanner = None
        self.policy_engine = None
        self.report_generator = None
    
    def setup_logging(self, verbose: bool):
        """Setup logging level"""
        level = logging.DEBUG if verbose else logging.INFO
        logging.getLogger().setLevel(level)
    
    def initialize_components(self, config_path: Optional[str] = None):
        """Initialize toolkit components"""
        # Load configuration
        self.config = POPIAConfig(config_path)
        
        # Initialize components
        ignore_patterns = self.config.config['scan']['ignore_patterns']
        self.scanner = POPIAScanner(ignore_patterns=ignore_patterns)
        
        policy_dir = self.config.config['policies'].get('custom_policy_dir')
        self.policy_engine = POPIAPolicyEngine(policy_dir=policy_dir)
        
        self.report_generator = POPIAReportGenerator()
        
        logger.info("POPIA toolkit components initialized")
    
    def cmd_scan(self, args):
        """Execute scan command"""
        logger.info(f"Starting POPIA scan of: {args.path}")
        
        # Determine scan type
        path = Path(args.path)
        if path.is_file():
            matches = self.scanner.scan_file(str(path))
            self.scanner.results = matches
        elif path.is_directory():
            extensions = args.extensions or self.config.config['scan']['extensions']
            matches = self.scanner.scan_directory(str(path), extensions)
        else:
            logger.error(f"Invalid path: {args.path}")
            return 1
        
        # Generate scan report
        report = self.scanner.generate_report(args.format)
        
        # Output report
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            logger.info(f"Scan results saved to {args.output}")
        else:
            print(report)
        
        # Summary
        total_matches = len(matches)
        severity_breakdown = self.scanner._get_severity_breakdown()
        logger.info(f"Scan complete: {total_matches} PII findings (H:{severity_breakdown['HIGH']}, M:{severity_breakdown['MEDIUM']}, L:{severity_breakdown['LOW']})")
        
        # Exit with error code if high severity findings
        return 1 if severity_breakdown['HIGH'] > 0 else 0
    
    def cmd_validate(self, args):
        """Execute validate command"""
        logger.info(f"Validating scan results: {args.input}")
        
        # Load scan results
        try:
            with open(args.input, 'r') as f:
                scan_data = json.load(f)
        except Exception as e:
            logger.error(f"Error loading scan results: {str(e)}")
            return 1
        
        # Run policy validation
        violations = self.policy_engine.validate_with_opa(scan_data, args.policy)
        
        # Create validation report
        validation_report = {
            'validation_timestamp': datetime.now().isoformat(),
            'policy_violations': len(violations),
            'compliance_status': 'PASS' if len(violations) == 0 else 'FAIL',
            'violations': [v.to_dict() for v in violations]
        }
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(validation_report, f, indent=2)
            logger.info(f"Validation results saved to {args.output}")
        else:
            print(json.dumps(validation_report, indent=2))
        
        # Summary
        logger.info(f"Validation complete: {len(violations)} policy violations found")
        
        # Return exit code based on compliance
        return 0 if validation_report['compliance_status'] == 'PASS' else 1
    
    def cmd_report(self, args):
        """Execute report command"""
        logger.info(f"Generating compliance report from: {args.input}")
        
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
            output_path = self.report_generator.generate_report(
                scan_data, validation_data, args.format, args.output
            )
            logger.info(f"Report generated successfully: {output_path}")
            return 0
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            return 1
    
    def cmd_init(self, args):
        """Initialize POPIA configuration"""
        config_path = args.config or '.popia-config.yaml'
        
        if Path(config_path).exists() and not args.force:
            logger.error(f"Configuration file already exists: {config_path}")
            logger.info("Use --force to overwrite")
            return 1
        
        self.config = POPIAConfig()
        self.config.create_default_config(config_path)
        
        # Create sample policy directory
        if args.with_policies:
            policy_dir = Path('./policies')
            policy_dir.mkdir(exist_ok=True)
            
            # Create sample policy
            sample_policy = '''
package popia.custom

import future.keywords.if

# Custom policy: No emails in configuration files
violation[msg] {
    match := input.matches[_]
    match.type == "EMAIL"
    contains(match.file_path, "config")
    msg := sprintf("Email found in config file: %v", [match.file_path])
}
            '''
            
            (policy_dir / 'custom.rego').write_text(sample_policy.strip())
            logger.info(f"Created sample policies in {policy_dir}")
        
        return 0
    
    def cmd_full_scan(self, args):
        """Execute full scan workflow (scan + validate + report)"""
        logger.info("Starting full POPIA compliance workflow")
        
        # Create temporary files for intermediate results
        with tempfile.TemporaryDirectory() as temp_dir:
            scan_results_file = Path(temp_dir) / 'scan_results.json'
            validation_results_file = Path(temp_dir) / 'validation_results.json'
            
            # Step 1: Scan
            logger.info("Step 1: Scanning for PII")
            scan_args = argparse.Namespace(
                path=args.path,
                output=str(scan_results_file),
                format='json',
                extensions=args.extensions
            )
            
            exit_code = self.cmd_scan(scan_args)
            if exit_code != 0 and args.fail_on_violations:
                logger.error("Scan found high severity violations. Stopping workflow.")
                return exit_code
            
            # Step 2: Validate (if enabled)
            validation_data = None
            if self.config.config['policies']['enabled']:
                logger.info("Step 2: Validating against policies")
                validate_args = argparse.Namespace(
                    input=str(scan_results_file),
                    output=str(validation_results_file),
                    policy=args.policy
                )
                
                exit_code = self.cmd_validate(validate_args)
                if exit_code != 0 and args.fail_on_violations:
                    logger.error("Policy validation failed. Stopping workflow.")
                    return exit_code
            
            # Step 3: Generate report
            logger.info("Step 3: Generating compliance report")
            report_format = args.format or self.config.config['reporting']['default_format']
            report_args = argparse.Namespace(
                input=str(scan_results_file),
                validation=str(validation_results_file) if validation_data else None,
                format=report_format,
                output=args.output
            )
            
            exit_code = self.cmd_report(report_args)
            
            logger.info("Full POPIA compliance workflow completed")
            return exit_code
    
    def run(self):
        """Main CLI entry point"""
        parser = argparse.ArgumentParser(
            description='POPIA Privacy-as-Code Toolkit',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''
Examples:
  %(prog)s scan --path ./myproject --output results.json
  %(prog)s validate --input results.json --output validation.json
  %(prog)s report --input results.json --format html --output report.html
  %(prog)s full-scan --path ./myproject --format pdf --output compliance_report.pdf
  %(prog)s init --with-policies
            '''
        )
        
        parser.add_argument('--config', help='Configuration file path')
        parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Scan command
        scan_parser = subparsers.add_parser('scan', help='Scan for PII')
        scan_parser.add_argument('--path', required=True, help='Path to scan')
        scan_parser.add_argument('--output', help='Output file path')
        scan_parser.add_argument('--format', choices=['json', 'text'], default='json', help='Output format')
        scan_parser.add_argument('--extensions', nargs='*', help='File extensions to scan')
        
        # Validate command
        validate_parser = subparsers.add_parser('validate', help='Validate against policies')
        validate_parser.add_argument('--input', required=True, help='Scan results JSON file')
        validate_parser.add_argument('--policy', help='Custom policy file (.rego)')
        validate_parser.add_argument('--output', help='Output file path')
        
        # Report command
        report_parser = subparsers.add_parser('report', help='Generate compliance report')
        report_parser.add_argument('--input', required=True, help='Scan results JSON file')
        report_parser.add_argument('--validation', help='Validation results JSON file')
        report_parser.add_argument('--format', choices=['pdf', 'html', 'md', 'markdown'], 
                                  default='html', help='Report format')
        report_parser.add_argument('--output', help='Output file path')
        
        # Init command
        init_parser = subparsers.add_parser('init', help='Initialize POPIA configuration')
        init_parser.add_argument('--config', help='Configuration file path')
        init_parser.add_argument('--with-policies', action='store_true', help='Create sample policies')
        init_parser.add_argument('--force', action='store_true', help='Overwrite existing config')
        
        # Full scan command
        full_scan_parser = subparsers.add_parser('full-scan', help='Complete workflow: scan + validate + report')
        full_scan_parser.add_argument('--path', required=True, help='Path to scan')
        full_scan_parser.add_argument('--policy', help='Custom policy file (.rego)')
        full_scan_parser.add_argument('--format', choices=['pdf', 'html', 'md', 'markdown'], help='Report format')
        full_scan_parser.add_argument('--output', help='Report output file path')
        full_scan_parser.add_argument('--extensions', nargs='*', help='File extensions to scan')
        full_scan_parser.add_argument('--fail-on-violations', action='store_true', 
                                    help='Exit with error on policy violations')
        
        # Parse arguments
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            return 1
        
        # Setup
        self.setup_logging(args.verbose)
        self.initialize_components(args.config)
        
        # Execute command
        try:
            if args.command == 'scan':
                return self.cmd_scan(args)
            elif args.command == 'validate':
                return self.cmd_validate(args)
            elif args.command == 'report':
                return self.cmd_report(args)
            elif args.command == 'init':
                return self.cmd_init(args)
            elif args.command == 'full-scan':
                return self.cmd_full_scan(args)
            else:
                logger.error(f"Unknown command: {args.command}")
                return 1
        
        except KeyboardInterrupt:
            logger.info("Operation cancelled by user")
            return 1
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1

def main():
    """Entry point for the CLI application"""
    cli = POPIACli()
    return cli.run()

if __name__ == '__main__':
    sys.exit(main())