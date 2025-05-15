# Memory Manipulation Bot

A C++ bot designed for scanning and manipulating memory addresses in external processes.

## Features

- Scan and identify specific memory addresses within target processes.
- Modify memory values at identified addresses.
- Log found addresses to a text file for future reference.
- Includes a precompiled executable (`Bot.exe`) for immediate use.

## Project Structure

- `Bot.cpp` – Main source code for the bot.
- `header.h` – Header file containing function declarations and necessary includes.
- `FoundAddresses.txt` – Output file logging discovered memory addresses.
- `Data/` – Directory potentially containing auxiliary data files.
- `.vscode/` – Visual Studio Code configuration files.
- `tempCodeRunnerFile.cpp` – Temporary file used during development.

## Requirements

- C++ compiler supporting C++11 or later (e.g., GCC, Clang, MSVC).
- Windows operating system (due to the use of Windows-specific APIs).

## Building the Project

1. Clone the repository:
   ```bash
   git clone https://github.com/Mkv47/Memory_Manipulation_Bot.git
   cd Memory_Manipulation_Bot
