"""
Scope management for bug bounty programs
Handles in-scope and out-of-scope targets
"""

import yaml
import os
from backend.utils.validator import ScopeValidator, validate_domain, validate_url, validate_ip
from backend.utils.logger import BugBountyLogger

class ScopeManager:
    def __init__(self, logger=None):
        self.validator = ScopeValidator()
        self.logger = logger or BugBountyLogger()
        self.program_name = None
        self.program_url = None
    
    def load_from_file(self, filepath):
        """Load scope from YAML file"""
        try:
            with open(filepath, 'r') as f:
                data = yaml.safe_load(f)
            
            self.program_name = data.get('program_name', 'Unknown')
            self.program_url = data.get('program_url', '')
            
            # Load in-scope targets
            in_scope = data.get('in_scope', [])
            self.validator.add_scope(in_scope, 'in')
            
            # Load out-of-scope targets
            out_of_scope = data.get('out_of_scope', [])
            self.validator.add_scope(out_of_scope, 'out')
            
            self.logger.success(f"Loaded scope for program: {self.program_name}")
            self.logger.info(f"In-scope targets: {len(in_scope)}")
            self.logger.info(f"Out-of-scope targets: {len(out_of_scope)}")
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to load scope file: {e}")
            return False
    
    def add_target(self, target, scope_type='in'):
        """Add a single target to scope"""
        # Validate target format
        if not (validate_domain(target) or validate_url(target) or validate_ip(target)):
            self.logger.warning(f"Invalid target format: {target}")
            return False
        
        self.validator.add_scope([target], scope_type)
        self.logger.info(f"Added {scope_type}-scope target: {target}")
        return True
    
    def check_target(self, target):
        """Check if target is in scope"""
        in_scope = self.validator.is_in_scope(target)
        
        if in_scope:
            self.logger.info(f"✓ Target is IN SCOPE: {target}")
        else:
            self.logger.warning(f"✗ Target is OUT OF SCOPE: {target}")
        
        return in_scope
    
    def get_in_scope_targets(self):
        """Get list of in-scope targets"""
        return self.validator.in_scope
    
    def get_out_of_scope_targets(self):
        """Get list of out-of-scope targets"""
        return self.validator.out_of_scope
    
    def save_to_file(self, filepath):
        """Save current scope to YAML file"""
        data = {
            'program_name': self.program_name or 'Bug Bounty Program',
            'program_url': self.program_url or '',
            'in_scope': self.validator.in_scope,
            'out_of_scope': self.validator.out_of_scope
        }
        
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w') as f:
                yaml.dump(data, f, default_flow_style=False)
            
            self.logger.success(f"Scope saved to: {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to save scope: {e}")
            return False
    
    def display_scope(self):
        """Display current scope configuration"""
        print("\n" + "="*60)
        print(f"PROGRAM: {self.program_name or 'Not Set'}")
        if self.program_url:
            print(f"URL: {self.program_url}")
        print("="*60)
        
        print("\n[IN SCOPE]")
        if self.validator.in_scope:
            for target in self.validator.in_scope:
                print(f"  ✓ {target}")
        else:
            print("  (none)")
        
        print("\n[OUT OF SCOPE]")
        if self.validator.out_of_scope:
            for target in self.validator.out_of_scope:
                print(f"  ✗ {target}")
        else:
            print("  (none)")
        
        print("\n" + "="*60 + "\n")
