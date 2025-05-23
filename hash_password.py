#!/usr/bin/env python3
"""
Bcrypt Password Utility - Complete Fixed Version with multiprocessing boost for password guessing
A secure tool for password hashing, verification, and recovery.
"""

import bcrypt
import sys
import os
import time
from rich.console import Console
from rich.prompt import Prompt, IntPrompt
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from typing import List, Optional
from multiprocessing import Pool, Manager, cpu_count

# Global console instance for consistent styling
console = Console()

def print_welcome() -> None:
    """Display the welcome banner."""
    welcome_text = Text("Bcrypt Password Hasher, Verifier & Guesser", style="bold cyan", justify="center")
    subtitle_text = Text("Secure Password Operations Tool", style="blue", justify="center")
    
    console.print(Panel(
        welcome_text,
        title="Welcome",
        subtitle=subtitle_text,
        border_style="green",
        padding=(1, 2)
    ))

def get_input(prompt_message: str, password: bool = False) -> str:
    """Get user input with styled prompt."""
    return Prompt.ask(
        f"[bold yellow]{prompt_message}[/bold yellow]",
        password=password
    )

def get_cost_factor() -> int:
    """Get valid bcrypt cost factor from user."""
    while True:
        try:
            cost = IntPrompt.ask(
                "[bold yellow]Enter bcrypt cost factor (4-31, default 10)[/bold yellow]",
                default=10
            )
            if 4 <= cost <= 31:
                return cost
            console.print("[bold red]Cost factor must be between 4 and 31.[/bold red]")
        except ValueError:
            console.print("[bold red]Please enter a valid number.[/bold red]")

def hash_password(password: str, cost: int = 10) -> str:
    """
    Hash a password using bcrypt.
    
    Args:
        password: The plaintext password to hash
        cost: The bcrypt cost factor (4-31)
    
    Returns:
        The hashed password as a string
    """
    try:
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=cost, prefix=b'2b')
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode('utf-8')
    except Exception as e:
        console.print(f"[bold red]Error hashing password: {str(e)}[/bold red]")
        sys.exit(1)

def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verify if a password matches a bcrypt hash.
    
    Args:
        password: The plaintext password to verify
        hashed_password: The bcrypt hash to compare against
    
    Returns:
        True if the password matches, False otherwise
    """
    try:
        password_bytes = password.encode('utf-8')
        hashed_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except Exception as e:
        # Log error but don't crash
        console.print(f"[bold red]Error verifying password: {str(e)}[/bold red]")
        return False

def load_passwords_from_file(file_path: str) -> List[str]:
    """
    Load passwords from a text file.
    
    Args:
        file_path: Path to the password wordlist file
    
    Returns:
        List of passwords (empty list if error occurs)
    """
    try:
        if not os.path.exists(file_path):
            console.print(f"[bold red]File not found: {file_path}[/bold red]")
            return []
        
        if os.path.getsize(file_path) > 10 * 1024 * 1024:  # 10MB warning
            console.print("[yellow]Warning: Large file detected. This may take a while...[/yellow]")
            
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        console.print(f"[bold red]Error reading file: {str(e)}[/bold red]")
        return []

def _worker_verify(args):
    """Worker function for multiprocessing: verify single password against hash.
    Args tuple: (password, hashed_password)
    Returns matched password or None
    """
    password, hashed_password = args
    if verify_password(password, hashed_password):
        return password
    return None

def guess_password(hashed_password: str, passwords: List[str]) -> Optional[str]:
    """
    Attempt to find a password matching the given hash using multiprocessing.
    
    Args:
        hashed_password: The bcrypt hash to match against
        passwords: List of potential passwords to test
    
    Returns:
        The matching password if found, None otherwise
    """
    total_passwords = len(passwords)
    console.print(Panel(
        Text("Starting password cracking process with multiprocessing boost...", style="bold cyan"),
        title="Password Cracking",
        border_style="cyan",
        padding=(1, 2)
    ))
    console.print("[bold yellow]Disclaimer:[/bold yellow] This process depends on your CPU speed and may take a long time for large wordlists or complex hashes.\n")

    start_time = time.perf_counter()

    # Prepare pool of worker processes
    cpu_cores = cpu_count()
    # Limit to max 4 or cpu_count to avoid overwhelming system (optional)
    workers = min(4, cpu_cores) if cpu_cores else 2

    # Create iterable of args tuples (password, hashed_password)
    tasks = ((p.strip(), hashed_password) for p in passwords if p.strip())

    matched_password = None

    with Progress(
        SpinnerColumn(style="cyan"),
        "[progress.description]{task.description}",
        BarColumn(bar_width=None),
        "[progress.percentage]{task.percentage:>3.0f}%",
        "•",
        TextColumn("[bold green]{task.completed}/{task.total} passwords tested"),
        "•",
        TimeElapsedColumn(),
        "•",
        TimeRemainingColumn(),
        console=console,
        transient=True,
    ) as progress:

        task = progress.add_task("Cracking in progress", total=total_passwords)

        with Pool(processes=workers) as pool:
            # imap_unordered returns results as soon as they're ready
            for result in pool.imap_unordered(_worker_verify, tasks, chunksize=10):
                progress.advance(task)
                if result is not None:
                    matched_password = result
                    # Found password, terminate workers asap
                    pool.terminate()
                    break

    elapsed = time.perf_counter() - start_time

    if matched_password:
        console.print(Panel(
            Text(f"Match found! Password: {matched_password}", style="bold green"),
            title="Success",
            border_style="green",
            padding=(1, 2)
        ))
        console.print(f"[bold cyan]Time elapsed:[/bold cyan] {elapsed:.2f} seconds")
        return matched_password
    else:
        console.print(Panel(
            Text("No matching password found in the provided list.", style="bold red"),
            title="Result",
            border_style="red",
            padding=(1, 2)
        ))
        console.print(f"[bold cyan]Time elapsed:[/bold cyan] {elapsed:.2f} seconds")
        return None

def hash_password_flow() -> None:
    """Handle the password hashing workflow."""
    password = get_input("Enter the password to hash")
    if not password:
        console.print("[bold red]Password cannot be empty.[/bold red]")
        return
    
    cost = get_cost_factor()
    hashed_password = hash_password(password, cost)
    
    console.print(Panel(
        Text(hashed_password, style="bold green"),
        title="Generated Bcrypt Hash",
        border_style="blue",
        padding=(1, 2)
    ))

def verify_password_flow() -> None:
    """Handle the password verification workflow."""
    hashed_password = get_input("Enter the bcrypt hash to verify against")
    if not hashed_password:
        console.print("[bold red]Hash cannot be empty.[/bold red]")
        return
    
    # Show typed input visibly (not masked)
    password = get_input("Enter the password to verify", password=False)
    if not password:
        console.print("[bold red]Password cannot be empty.[/bold red]")
        return
    
    if verify_password(password, hashed_password):
        console.print(Panel(
            Text("Password matches the hash!", style="bold green"),
            title="Verification Result",
            border_style="green",
            padding=(1, 2)
        ))
    else:
        console.print(Panel(
            Text("Password does not match the hash.", style="bold red"),
            title="Verification Result",
            border_style="red",
            padding=(1, 2)
        ))

def guess_password_flow() -> None:
    """Handle the password guessing workflow."""
    hashed_password = get_input("Enter the bcrypt hash to guess")
    if not hashed_password:
        console.print("[bold red]Hash cannot be empty.[/bold red]")
        return
    
    file_path = get_input("Enter the path to the password list file (e.g., passwords.txt)")
    if not file_path:
        console.print("[bold red]File path cannot be empty.[/bold red]")
        return
    
    passwords = load_passwords_from_file(file_path)
    if not passwords:
        console.print("[bold red]No valid passwords loaded from file.[/bold red]")
        return
    
    guess_password(hashed_password, passwords)

def main_menu() -> None:
    """Display the main menu and handle user choices."""
    while True:
        console.print("\n[bold cyan]Main Menu:[/bold cyan]")
        console.print("[1] Hash a password")
        console.print("[2] Verify a password")
        console.print("[3] Guess password from hash using file")
        console.print("[4] Exit")
        
        choice = Prompt.ask(
            "[bold yellow]Enter your choice (1-4)[/bold yellow]", 
            choices=["1", "2", "3", "4"]
        )
        
        if choice == "1":
            hash_password_flow()
        elif choice == "2":
            verify_password_flow()
        elif choice == "3":
            guess_password_flow()
        else:
            console.print("[bold magenta]Exiting program.[/bold magenta]")
            sys.exit(0)

def main() -> None:
    """Main program entry point."""
    try:
        print_welcome()
        main_menu()
    except KeyboardInterrupt:
        console.print("\n[bold magenta]Operation cancelled by user.[/bold magenta]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[bold red]Unexpected error: {str(e)}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    main()


