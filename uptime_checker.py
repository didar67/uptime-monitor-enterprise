#!/usr/bin/env python3
"""
Enterprise Website Uptime Monitor with Parallel Checks & Notifications
"""

import os
import sys
import logging
from logging.handlers import RotatingFileHandler
import argparse
import yaml
import time
from typing import Any, Dict, List, Optional, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import ConnectionError, RequestException, Timeout
from smtplib import SMTP, SMTPException
from email.message import EmailMessage

try:
    from twilio.rest import Client as TwilioClient
except ImportError:
    TwilioClient = None

def initialize_logger(log_file_path: str, max_file_size: int, backup_count: int) -> logging.Logger:
    logger = logging.getLogger('EnterpriseUptimeMonitor')
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(levelname)-8s - %(threadName)-12s - %(message)s")

    if not logger.handlers:
        file_handler = RotatingFileHandler(log_file_path, maxBytes=max_file_size, backupCount=backup_count)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger

def load_config(path: str) -> dict:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Configuration file not found: {path}")
    with open(path, 'r', encoding='utf-8') as file:
        return yaml.safe_load(file)

class NotificationManager:
    def __init__(self, config: dict, logger: logging.Logger):
        self.logger = logger
        self.email_enabled = config.get("enable_email", False)
        self.sms_enabled = config.get("enable_sms", False)

        email_cfg = config.get("email", {})
        self.smtp_server = email_cfg.get("smtp_server", "")
        self.smtp_port = email_cfg.get("smtp_port", 587)
        self.sender_email = email_cfg.get("sender_email")
        self.sender_password = email_cfg.get("sender_password")
        self.recipient_emails = email_cfg.get("recipient_emails", [])

        sms_cfg = config.get("sms", {})
        self.twilio_sid = sms_cfg.get("account_sid")
        self.twilio_token = sms_cfg.get("auth_token")
        self.from_phone = sms_cfg.get("from_phone")
        self.twilio_to_phones = sms_cfg.get("to_phones", [])

        if self.sms_enabled and TwilioClient:
            self.twilio_client = TwilioClient(self.twilio_sid, self.twilio_token)
        else:
            self.twilio_client = None
            if self.sms_enabled:
                self.logger.warning("Twilio package not installed; SMS notifications disabled.")

    def send_email_alert(self, subject: str, body: str) -> None:
        if not self.email_enabled:
            self.logger.debug("Email notification is disabled in config.")
            return
        if not all([self.smtp_server, self.smtp_port, self.sender_password]):
            self.logger.error("Incomplete email configuration; cannot send email.")
            return

        try:
            message = EmailMessage()
            message["From"] = self.sender_email
            message["To"] = ", ".join(self.recipient_emails)
            message["Subject"] = subject
            message.set_content(body)

            with SMTP(self.smtp_server, self.smtp_port) as smtp:
                smtp.starttls()
                smtp.login(self.sender_email, self.sender_password)
                smtp.send_message(message)

            self.logger.info("Email alert sent successfully.")
        except SMTPException as e:
            self.logger.error(f"Failed to send email alert: {e}")

    def send_sms_alert(self, message_body: str) -> None:
        if not self.sms_enabled:
            self.logger.debug("SMS notification is disabled in config.")
            return
        if not self.twilio_client:
            self.logger.error("Twilio client not initialized; cannot send SMS.")
            return

        for to_phone in self.twilio_to_phones:
            try:
                message = self.twilio_client.messages.create(
                    body=message_body,
                    from_=self.from_phone,
                    to=to_phone
                )
                self.logger.info(f"SMS alert sent to {to_phone}, SID: {message.sid}")
            except Exception as e:
                self.logger.error(f"Failed to send SMS to {to_phone}: {e}")

def is_website_response(
    url: str,
    timeout: int,
    retries: int,
    headers: Optional[Dict[str, str]],
    auth_info: Optional[Union[Dict[str, str], None]],
    dry_run: bool,
    logger: logging.Logger,
) -> bool:
    if dry_run:
        logger.info(f"[DRY RUN] Simulated check for: {url}")
        return True

    auth = None
    if auth_info and isinstance(auth_info, dict):
        username = auth_info.get("username")
        password = auth_info.get("password")
        if username and password:
            auth = HTTPBasicAuth(username, password)

    for attempt in range(1, retries + 1):
        try:
            logger.debug(f"Attempt {attempt} for URL: {url}")
            response = requests.head(
                url,
                headers=headers,
                auth=auth,
                timeout=timeout,
                allow_redirects=True
            )
            if 200 <= response.status_code < 400:
                logger.info(f"✅ {url} is UP (Status: {response.status_code})")
                return True
            else:
                logger.warning(f"⚠️ {url} returned status {response.status_code} on attempt {attempt}")
        except (ConnectionError, Timeout) as err:
            logger.warning(f"Connection issue on attempt {attempt} for {url}: {err}")
        except RequestException as err:
            logger.error(f"Request error for {url}: {err}")
        except Exception as err:
            logger.error(f"Unexpected error for {url}: {err}")
            break
        time.sleep(1)

    logger.error(f"❌ {url} is DOWN after {retries} attempts")
    return False

def parse_cli_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enterprise Website Uptime Monitor with Notifications")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--config", type=str, help="Path to YAML config file with URLs and settings")
    group.add_argument("urls", nargs="*", help="One or more URLs to check (space-separated)")
    parser.add_argument("--dry_run", action="store_true", help="Simulate checks without making real HTTP requests")
    return parser.parse_args()

def main() -> None:
    try:
        args = parse_cli_arguments()

        if args.urls:
            urls_info = [{"url": u, "headers": {}, "auth": None} for u in args.urls]
            timeout_sec = 5
            max_retry = 3
            max_workers = 5
            log_path = "uptime_checker.log"
            log_max_bytes = 1048576
            log_backup = 3
            notification_config = {}
        else:
            config = load_config(args.config)
            urls_info = config.get("urls", [])
            timeout_sec = config.get("timeout_seconds", 5)
            max_retry = config.get("max_retries", 3)
            max_workers = config.get("max_workers", 5)
            log_path = config.get("log_file", "uptime_checker.log")
            log_max_bytes = config.get("log_max_bytes", 1048576)
            log_backup = config.get("log_backup_count", 3)
            notification_config = config.get("notification", {})

        logger = initialize_logger(log_path, log_max_bytes, log_backup)
        logger.info("Starting Enterprise Website Uptime Monitor")
        logger.debug(f"Configuration: timeout={timeout_sec}, retries={max_retry}, max_workers={max_workers}")

        notifier = NotificationManager(notification_config, logger)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {
                    executor.submit(
                        is_website_response,
                        site["url"],
                        timeout_sec,
                        max_retry,
                        site.get("headers"),
                        site.get("auth"),
                        args.dry_run,
                        logger,
                    ): site["url"]
                    for site in urls_info
                }

            down_sites: List[str] = []

            for future in as_completed(future_to_url):
                site_url = future_to_url[future]
                try:
                    result = future.result()
                    if not result:
                        down_sites.append(site_url) 
                except Exception as exc:
                    logger.error(f"Error checking {site_url}: {exc}")
                    down_sites.append(site_url) 

        if down_sites:
            alert_subject = "ALERT: Website Downtime Detected"
            alert_body = "The following sites are down or unreachable:\n" + "\n".join(down_sites)
            logger.warning(alert_body)
            notifier.send_email_alert(alert_subject, alert_body)
            notifier.send_sms_alert(alert_body)
        else:
            logger.info("All websites are UP and reachable.")

        logger.info("Monitoring run complete")

    except FileNotFoundError as err:
        print(f"[FATAL] Configuration file error: {err}")
        sys.exit(1)
    except PermissionError as err:
        print(f"[FATAL] Permission error: {err}")
        sys.exit(1)
    except yaml.YAMLError as err:
        print(f"[FATAL] YAML parsing error: {err}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[INFO] Execution interrupted by user.")
        sys.exit(0)
    except Exception as err:
        print(f"[FATAL] Unexpected error: {err}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[FATAL] Unexpected error occurred: {e}")
    else:
        print("[INFO] Script executed successfully.")
    finally:
        print("[INFO] Script execution finished.")
