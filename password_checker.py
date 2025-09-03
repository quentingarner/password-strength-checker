#!/usr/bin/env python3
"""
Password Strength Checker
A Python tool that evaluates password strength and provides security recommendations.
"""

import re
import sys

class PasswordChecker:
    def __init__(self):
        # Common weak passwords to check against
        self.common_passwords = [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            '1234567890', 'password1', 'qwerty123', 'admin123'
        ]
    
    def check_length(self, password):
        """Check if password meets length requirements"""
        length = len(password)
        if length < 8:
            return False, "Password should be at least 8 characters long"
        elif length < 12:
            return True, "Good length, but 12+ characters is even better"
        else:
            return True, "Excellent length"
    
    def check_character_variety(self, password):
        """Check for different character types"""
        checks = {
            'lowercase': re.search(r'[a-z]', password) is not None,
            'uppercase': re.search(r'[A-Z]', password) is not None,
            'digits': re.search(r'\d', password) is not None,
            'special': re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>?]', password) is not None
        }
        
        variety_count = sum(checks.values())
        missing_types = [key for key, value in checks.items() if not value]
        
        if variety_count < 3:
            return False, f"Include {', '.join(missing_types)} characters"
        elif variety_count == 3:
            return True, f"Good variety. Consider adding: {', '.join(missing_types)}"
        else:
            return True, "Excellent character variety"
    
    def check_common_passwords(self, password):
        """Check against common weak passwords"""
        password_lower = password.lower()
        for common in self.common_passwords:
            if common in password_lower:
                return False, f"Avoid common passwords like '{common}'"
        return True, "Not a common weak password"
    
    def check_patterns(self, password):
        """Check for predictable patterns"""
        # Check for sequential numbers
        if re.search(r'123|234|345|456|567|678|789|890', password):
            return False, "Avoid sequential numbers (123, 456, etc.)"
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            return False, "Avoid repeating the same character 3+ times"
        
        # Check for keyboard patterns
        keyboard_patterns = ['qwer', 'asdf', 'zxcv', 'qaz', 'wsx']
        password_lower = password.lower()
        for pattern in keyboard_patterns:
            if pattern in password_lower:
                return False, f"Avoid keyboard patterns like '{pattern}'"
        
        return True, "No obvious patterns detected"
    
    def calculate_strength(self, password):
        """Calculate overall password strength"""
        checks = [
            self.check_length(password),
            self.check_character_variety(password),
            self.check_common_passwords(password),
            self.check_patterns(password)
        ]
        
        passed_checks = sum(1 for check, _ in checks if check)
        total_checks = len(checks)
        
        # Calculate strength percentage
        strength_percentage = (passed_checks / total_checks) * 100
        
        # Determine strength level with stricter criteria
        # If it fails common password or length check, it's automatically weak
        length_passed = checks[0][0]
        common_password_passed = checks[2][0]
        
        if not length_passed or not common_password_passed:
            strength_level = "WEAK"
            color_code = "\033[91m"  # Red
        elif strength_percentage < 75:
            strength_level = "WEAK"
            color_code = "\033[91m"  # Red
        elif strength_percentage < 100:
            strength_level = "MEDIUM"
            color_code = "\033[93m"  # Yellow
        else:
            strength_level = "STRONG"
            color_code = "\033[92m"  # Green
        
        reset_code = "\033[0m"  # Reset color
        
        return {
            'strength_level': strength_level,
            'strength_percentage': strength_percentage,
            'color_code': color_code,
            'reset_code': reset_code,
            'checks': checks
        }
    
    def display_results(self, password, results):
        """Display password strength results"""
        print(f"\n{'='*50}")
        print(f"PASSWORD STRENGTH ANALYSIS")
        print(f"{'='*50}")
        
        # Display overall strength
        strength = results['strength_level']
        percentage = results['strength_percentage']
        color = results['color_code']
        reset = results['reset_code']
        
        print(f"Overall Strength: {color}{strength}{reset} ({percentage:.0f}%)")
        print(f"\nDetailed Analysis:")
        print(f"-" * 30)
        
        # Display individual check results
        check_names = ["Length", "Character Variety", "Common Passwords", "Pattern Check"]
        
        for i, (passed, message) in enumerate(results['checks']):
            status = "✓" if passed else "✗"
            status_color = "\033[92m" if passed else "\033[91m"
            print(f"{status_color}{status}{reset} {check_names[i]}: {message}")
        
        # Provide recommendations
        print(f"\n{'='*50}")
        if strength == "WEAK":
            print("🚨 RECOMMENDATIONS:")
            print("• Your password needs significant improvement")
            print("• Address the failed checks above")
            print("• Consider using a password manager")
        elif strength == "MEDIUM":
            print("⚠️  RECOMMENDATIONS:")
            print("• Your password is decent but could be stronger")
            print("• Address any remaining issues shown above")
            print("• Consider making it longer if possible")
        else:
            print("✅ EXCELLENT:")
            print("• Your password meets security best practices")
            print("• Keep using strong, unique passwords")
            print("• Consider using a password manager for all accounts")


def main():
    """Main function to run the password checker"""
    print("🔒 Password Strength Checker")
    print("=" * 50)
    print("This tool will analyze your password strength.")
    print("Note: Your password is not stored or transmitted anywhere.")
    print()
    
    # Ask for strict mode
    strict_input = input("Enable strict mode? (y/n): ").lower().strip()
    strict_mode = strict_input.startswith('y')
    
    if strict_mode:
        print("\n🔴 STRICT MODE ENABLED")
        print("• Minimum 12 characters required")
        print("• All character types required (upper, lower, digits, special)")
        print("• Enhanced pattern detection")
        print("• Expanded weak password database")
    else:
        print("\n🟡 STANDARD MODE")
        print("• Minimum 8 characters required")
        print("• At least 3 character types required")
        print("• Basic security checks")
    
    print()
    checker = PasswordChecker(strict_mode=strict_mode)
    
    try:
        # Get password input (hidden for security)
        import getpass
        password = getpass.getpass("Enter password to check: ")
        
        if not password:
            print("Error: No password entered.")
            return
        
        # Analyze password
        results = checker.calculate_strength(password)
        
        # Display results
        checker.display_results(password, results)
        
    except KeyboardInterrupt:
        print("\n\nPassword check cancelled.")
        sys.exit(0)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()