# VirusTotal File Scanner

A Python-based tool that scans files for potential viruses and malware by leveraging the VirusTotal API. This project includes multithreaded and multiprocess implementations to optimize scanning performance for large volumes of files, detailed timing metrics, and synchronized data handling through semaphores and producer-consumer models.

---

## Project Overview

This tool was developed to improve efficiency in scanning files through the VirusTotal API by implementing various concurrency models and synchronization techniques. The scanner can run in sequential (single-thread) and parallel (multi-thread and multi-process) modes. Execution time and performance metrics are logged for analysis, ensuring robust and scalable file handling.

---

## Features

- **VirusTotal API Integration**: Sends files to VirusTotal for virus and malware scanning, fetching comprehensive reports for each file.
- **Sequential and Concurrent Models**: Includes monothreaded (single process), multiprocess, and multithreaded implementations for performance comparison.
- **Execution Time Logging**: Captures and displays execution time for sequential and parallel implementations.
- **Inter-process Communication**: Uses Pipes and Message Queues to manage inter-process data exchange.
- **Synchronization with Semaphores**: Ensures safe resource handling across threads and processes.
- **Producer-Consumer Model**: Optimizes task handling across threads using a producer-consumer pattern.
- **PDF Report Generation**: Summarizes scan results for all files in a clear, readable format.
- **User Interface**: Basic GUI with file selection and progress display.

---

## Getting Started

### Prerequisites

 **Python 3.8+**
 **VirusTotal API Key**

### Required Python Libraries

pip install requests psutil tkinter reportlab
Installation
Clone the repository and navigate to the project directory:

## git clone https://github.com/yourusername/VirusTotal_File_Scanner.git

cd VirusTotal_File_Scanner
Configuration

Add your VirusTotal API key to a .env file:
VIRUSTOTAL_API_KEY=your_api_key_here
Usage
Run the main script to start scanning files in a directory:

python VirusTotal_File_Scanner.py
Command Line Options
--path <directory>: Specifies the directory for files to be scanned.
--threads <num_threads>: Sets the number of threads for scanning (default: 4).
--processes <num_processes>: Sets the number of processes (for multiprocessing).
GUI Mode

## To use the GUI, execute the script without additional arguments. In GUI mode, you can:

Select a directory containing files.
Monitor scan progress with a progress bar.
View detailed execution time upon completion.
Dashboard Mode (Optional)
Run dashboard.py to view real-time CPU and memory usage during scanning.

Code Structure
## VirusTotal_File_Scanner.py: Main script containing the core scanning logic.

## dashboard: Provides a visualization dashboard (using Dash).

## report_generator: Generates PDF reports from scan results.
## utils/: Contains helper functions for database handling, API integration, and concurrency models.

Examples
Sequential Mode

from VirusTotal_File_Scanner import scan_file_sequential
scan_file_sequential("example_file.txt")
Multi-Threaded Mode

from VirusTotal_File_Scanner import scan_files_multithread
scan_files_multithread(["file1.txt", "file2.txt"], threads=5)
Multi-Processing Mode with Semaphore

from VirusTotal_File_Scanner import scan_files_multiprocess
scan_files_multiprocess(["file1.txt", "file2.txt"], processes=3)

## Future Improvements
Cloud Integration: Expanding to cloud providers for scalability.
Enhanced Error Handling: Adding robust error handling and retry mechanisms.
Improved Reporting: Adding detailed analytics to generated reports.

## Contributing
Contributions are welcome! Please submit issues, requests, or pull requests to improve the project.
