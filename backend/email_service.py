"""
Email Service Module

This module provides email sending functionality supporting multiple providers:
- SMTP (default)
- SendGrid
- Console logging (for development)

Configuration is done via environment variables.
"""

import os
import smtplib
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables from .env file (in parent directory)
env_path = Path(__file__).parent.parent / ".env"
load_dotenv(env_path)
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Optional
import secrets


class EmailConfig:
    """Email configuration from environment variables."""
    
    # Email provider: "smtp", "sendgrid", "console"
    EMAIL_PROVIDER = os.getenv("EMAIL_PROVIDER", "console")
    
    # SMTP Configuration
    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", SMTP_USER)
    SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "Auth Service")
    SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
    
    # SendGrid Configuration
    SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY", "")
    SENDGRID_FROM_EMAIL = os.getenv("SENDGRID_FROM_EMAIL", "")
    SENDGRID_FROM_NAME = os.getenv("SENDGRID_FROM_NAME", "Auth Service")
    
    # Frontend URL for reset links
    FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
    
    # Password reset token expiry in minutes
    PASSWORD_RESET_EXPIRY = int(os.getenv("PASSWORD_RESET_EXPIRY", "60"))


class EmailTemplate:
    """Email template generator for various email types."""
    
    @staticmethod
    def password_reset_email(
        user_name: str,
        reset_token: str,
        reset_url: str,
        expiry_hours: int = 1
    ) -> tuple[str, str]:
        """
        Generate password reset email content.
        
        Returns:
            tuple: (html_content, text_content)
        """
        full_reset_url = f"{reset_url}?token={reset_token}"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Reset Your Password</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
                <h1 style="color: white; margin: 0;">Password Reset</h1>
            </div>
            
            <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #ddd; border-top: none;">
                <p>Hello <strong>{user_name}</strong>,</p>
                
                <p>We received a request to reset your password. Click the button below to create a new password:</p>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{full_reset_url}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
                        Reset Password
                    </a>
                </div>
                
                <p>Or copy and paste this link into your browser:</p>
                <p style="background: #fff; padding: 15px; border-radius: 5px; word-break: break-all; border: 1px solid #ddd;">
                    {full_reset_url}
                </p>
                
                <p style="color: #666; font-size: 14px;">
                    <strong>⚠️ This link will expire in {expiry_hours} hour(s).</strong><br>
                    If you didn't request this password reset, you can safely ignore this email.
                </p>
                
                <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">
                
                <p style="color: #888; font-size: 12px; text-align: center;">
                    This is an automated email. Please do not reply to this message.
                </p>
            </div>
        </body>
        </html>
        """
        
        text_content = f"""
Hello {user_name},

We received a request to reset your password.

To reset your password, please visit the following link:
{full_reset_url}

This link will expire in {expiry_hours} hour(s).

If you didn't request this password reset, you can safely ignore this email.

---
This is an automated email. Please do not reply to this message.
        """
        
        return html_content, text_content

    @staticmethod
    def password_changed_notification(user_name: str) -> tuple[str, str]:
        """
        Generate password changed notification email.
        
        Returns:
            tuple: (html_content, text_content)
        """
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Password Changed</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
                <h1 style="color: white; margin: 0;">✓ Password Changed</h1>
            </div>
            
            <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #ddd; border-top: none;">
                <p>Hello <strong>{user_name}</strong>,</p>
                
                <p>Your password has been successfully changed.</p>
                
                <p style="background: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #ffc107;">
                    <strong>Security Notice:</strong> If you did not make this change, please contact support immediately and secure your account.
                </p>
                
                <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">
                
                <p style="color: #888; font-size: 12px; text-align: center;">
                    This is an automated email. Please do not reply to this message.
                </p>
            </div>
        </body>
        </html>
        """
        
        text_content = f"""
Hello {user_name},

Your password has been successfully changed.

SECURITY NOTICE: If you did not make this change, please contact support immediately and secure your account.

---
This is an automated email. Please do not reply to this message.
        """
        
        return html_content, text_content


class EmailService:
    """Email service for sending various types of emails."""
    
    def __init__(self):
        self.config = EmailConfig()
        self.template = EmailTemplate()
    
    def send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: str
    ) -> bool:
        """
        Send an email using the configured provider.
        
        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML version of the email
            text_content: Plain text version of the email
            
        Returns:
            bool: True if email was sent successfully
        """
        provider = self.config.EMAIL_PROVIDER.lower()
        
        if provider == "smtp":
            return self._send_via_smtp(to_email, subject, html_content, text_content)
        elif provider == "sendgrid":
            return self._send_via_sendgrid(to_email, subject, html_content, text_content)
        elif provider == "console":
            return self._send_via_console(to_email, subject, html_content, text_content)
        else:
            print(f"Unknown email provider: {provider}")
            return False
    
    def _send_via_smtp(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: str
    ) -> bool:
        """Send email via SMTP."""
        try:
            print(f"[SMTP DEBUG] Starting SMTP send...")
            print(f"[SMTP DEBUG] Host: {self.config.SMTP_HOST}")
            print(f"[SMTP DEBUG] Port: {self.config.SMTP_PORT}")
            print(f"[SMTP DEBUG] User: {self.config.SMTP_USER}")
            print(f"[SMTP DEBUG] From: {self.config.SMTP_FROM_EMAIL}")
            print(f"[SMTP DEBUG] To: {to_email}")
            print(f"[SMTP DEBUG] TLS: {self.config.SMTP_USE_TLS}")
            
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"{self.config.SMTP_FROM_NAME} <{self.config.SMTP_FROM_EMAIL}>"
            msg["To"] = to_email
            
            msg.attach(MIMEText(text_content, "plain"))
            msg.attach(MIMEText(html_content, "html"))
            
            print(f"[SMTP DEBUG] Connecting to SMTP server...")
            
            with smtplib.SMTP(self.config.SMTP_HOST, self.config.SMTP_PORT) as server:
                print(f"[SMTP DEBUG] Connected, setting debug level...")
                server.set_debuglevel(1)  # Enable SMTP debug output
                
                if self.config.SMTP_USE_TLS:
                    print(f"[SMTP DEBUG] Starting TLS...")
                    server.starttls()
                
                if self.config.SMTP_USER and self.config.SMTP_PASSWORD:
                    print(f"[SMTP DEBUG] Logging in...")
                    server.login(self.config.SMTP_USER, self.config.SMTP_PASSWORD)
                    print(f"[SMTP DEBUG] Login successful")
                
                print(f"[SMTP DEBUG] Sending email...")
                server.sendmail(self.config.SMTP_FROM_EMAIL, to_email, msg.as_string())
                print(f"[SMTP DEBUG] Email sent!")
            
            print(f"✅ Email sent successfully to {to_email} via SMTP")
            return True
            
        except Exception as e:
            print(f"❌ Failed to send email via SMTP: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _send_via_sendgrid(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: str
    ) -> bool:
        """Send email via SendGrid API."""
        try:
            import requests
            
            headers = {
                "Authorization": f"Bearer {self.config.SENDGRID_API_KEY}",
                "Content-Type": "application/json"
            }
            
            data = {
                "personalizations": [
                    {
                        "to": [{"email": to_email}],
                        "subject": subject
                    }
                ],
                "from": {
                    "email": self.config.SENDGRID_FROM_EMAIL,
                    "name": self.config.SENDGRID_FROM_NAME
                },
                "content": [
                    {"type": "text/plain", "value": text_content},
                    {"type": "text/html", "value": html_content}
                ]
            }
            
            response = requests.post(
                "https://api.sendgrid.com/v3/mail/send",
                headers=headers,
                json=data
            )
            
            if response.status_code == 202:
                print(f"✅ Email sent successfully to {to_email} via SendGrid")
                return True
            else:
                print(f"❌ SendGrid error: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Failed to send email via SendGrid: {e}")
            return False
    
    def _send_via_console(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: str
    ) -> bool:
        """Log email to console (for development)."""
        print("\n" + "="*60)
        print("📧 EMAIL (Console Mode)")
        print("="*60)
        print(f"To: {to_email}")
        print(f"Subject: {subject}")
        print("-"*60)
        print(text_content)
        print("="*60 + "\n")
        return True
    
    def send_password_reset_email(
        self,
        to_email: str,
        user_name: str,
        reset_token: str
    ) -> bool:
        """
        Send a password reset email.
        
        Args:
            to_email: User's email address
            user_name: User's name
            reset_token: Password reset token
            
        Returns:
            bool: True if email was sent successfully
        """
        reset_url = f"{self.config.FRONTEND_URL}/reset-password"
        expiry_hours = self.config.PASSWORD_RESET_EXPIRY // 60
        
        html_content, text_content = self.template.password_reset_email(
            user_name=user_name,
            reset_token=reset_token,
            reset_url=reset_url,
            expiry_hours=expiry_hours or 1
        )
        
        return self.send_email(
            to_email=to_email,
            subject="Reset Your Password",
            html_content=html_content,
            text_content=text_content
        )
    
    def send_password_changed_email(
        self,
        to_email: str,
        user_name: str
    ) -> bool:
        """
        Send a password changed notification email.
        
        Args:
            to_email: User's email address
            user_name: User's name
            
        Returns:
            bool: True if email was sent successfully
        """
        html_content, text_content = self.template.password_changed_notification(
            user_name=user_name
        )
        
        return self.send_email(
            to_email=to_email,
            subject="Your Password Has Been Changed",
            html_content=html_content,
            text_content=text_content
        )


def generate_reset_token() -> str:
    """Generate a secure password reset token."""
    return secrets.token_urlsafe(32)


# Global email service instance
email_service = EmailService()