import os
import logging
import time
import sqlite3
import requests
import hashlib
from tkinter import Tk, Label, Button, filedialog, ttk, Text, Entry, Frame
from tkinter import font as tkfont
from concurrent.futures import ThreadPoolExecutor  
from datetime import datetime
from dash import Dash, html, dcc
from dash.dependencies import Output, Input
from dash.dash_table import DataTable
import psutil
import threading
import queue


# VirusTotal API Key (replace with your actual API key)
API_KEY = '58d38393d2587da5d889211cd2b09f622f6be330e13b1bba5f57c50a8db5f871'



# Semaphore to limit the number of concurrent threads accessing a resource
semaphore = threading.Semaphore(3)  # Allow up to 3 threads to run concurrently

# Function to check system load and adjust sleep time dynamically
def adjust_sleep_time():
    cpu_usage = psutil.cpu_percent()  # Get current CPU usage as a percentage
    active_threads = threading.active_count()  # Get the number of active threads

    # Example logic to adjust sleep time based on system load and active threads
    if cpu_usage > 80:  # If CPU usage is high
        sleep_time = 2  # Increase sleep time if CPU is heavily used
    elif active_threads > 10:  # If there are many active threads
        sleep_time = 1.5  # Add a slight delay to reduce load
    else:
        sleep_time = 1  # Default sleep time when system is idle or under low load

    return sleep_time

def access_resource(thread_id):
    """Simulate accessing a shared resource with dynamic sleep time."""
    print(f"Thread {thread_id} is waiting for the semaphore.")
    with semaphore:
        print(f"Thread {thread_id} has acquired the semaphore.")
       
        # Adjust sleep time based on system load and active threads
        sleep_time = adjust_sleep_time()
        print(f"Thread {thread_id} will sleep for {sleep_time} seconds.")
       
        time.sleep(sleep_time)  # Simulate some work with the resource (e.g., API request)
        print(f"Thread {thread_id} is releasing the semaphore.")

def run_threads():
    """Create and run multiple threads that will compete for the semaphore."""
    threads = []

    # Create 5 threads to access the resource
    for i in range(1, 6):
        thread = threading.Thread(target=access_resource, args=(i,))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

# Run the threads
if __name__ == '__main__':
    run_threads()


# Configure logging for better tracking of events and errors
logging.basicConfig(level=logging.INFO)

# Set up SQLite database for caching scan results
def setup_database():
    """Initialize the SQLite database for storing scan results."""
    conn = sqlite3.connect('cache.db')
    cursor = conn.cursor()
    cursor.execute(
        'CREATE TABLE IF NOT EXISTS vt_cache (hash TEXT PRIMARY KEY, result TEXT)'
    )
    conn.commit()
    conn.close()

setup_database()

def scan_with_virustotal(file_hash):
    """Scan a file using VirusTotal API."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            logging.error(f"VirusTotal Error: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        logging.error(f"VirusTotal Exception: {e}")
        return None

def process_file(file_path):
    """Process a single file and return its metadata and scan result."""
    try:
        file_size = os.path.getsize(file_path)
        creation_time = os.path.getctime(file_path)
        formatted_creation_time = datetime.fromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')

        # Calculate SHA256 hash for the file
        hash_sha256 = hashlib.sha256()
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):
                hash_sha256.update(chunk)
        file_hash = hash_sha256.hexdigest()

        # Scan the file with VirusTotal
        vt_result = scan_with_virustotal(file_hash)

        return file_path, file_hash, file_size, formatted_creation_time, vt_result, "Completed"
    except Exception as e:
        logging.error(f"Error processing file {file_path}: {e}")
        return file_path, None, None, None, None, "Error"

def batch_process_files(files, thread_count):
    """Process multiple files concurrently using threading."""
    start_time = time.time()  # Record the start time
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        results = list(executor.map(process_file, files))
    end_time = time.time()  # Record the end time

    execution_time = end_time - start_time  # Calculate execution time
    logging.info(f"Total execution time for {len(files)} files: {execution_time:.2f} seconds.")
    return results, execution_time

def generate_report(results, filename='scan_report.pdf'):
    """Generate a PDF report summarizing scan results."""
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    c = canvas.Canvas(filename, pagesize=letter)
    c.drawString(100, 750, "Scan Report")
    for i, (file_path, file_hash, file_size, creation_date, vt_result, status) in enumerate(results, start=1):
        c.drawString(100, 750 - i * 20, f"{file_path}: {file_hash} - Size: {file_size} bytes - Created: {creation_date} - Status: {status}")
    c.save()

def get_files_from_directory(directory):
    """Retrieve all files from the selected directory."""
    return [os.path.join(directory, file) for file in os.listdir(directory) if os.path.isfile(os.path.join(directory, file))]

# Tkinter GUI for user interaction
def start_tkinter():
    """Start the Tkinter GUI application."""
    root = Tk()
    root.title("Directory Scanner")
    root.geometry("600x500")
    root.resizable(False, False)

    # Define font styles
    heading_font = tkfont.Font(family="Helvetica", size=14, weight="bold")
    label_font = tkfont.Font(family="Helvetica", size=10)
   
    # Main frame to contain all elements
    main_frame = Frame(root, padx=20, pady=20, bg="#333333")
    main_frame.pack(fill="both", expand=True)

    # Header label
    Label(main_frame, text="VirusTotal File Scanner", font=heading_font, fg="#333333", bg="#178e90").grid(row=0, column=0, columnspan=2, pady=10)

    # Text widget for file preview
    preview_text = Text(main_frame, wrap='word', height=10, width=60, bg="#f8f9f9", fg="#333333", bd=1)
    preview_text.grid(row=1, column=0, columnspan=2, pady=10)

    # Label for execution time
    execution_time_label = Label(main_frame, text="Execution Time: 0.00 seconds", font=label_font, bg="#333333", fg="white")
    execution_time_label.grid(row=2, column=0, columnspan=2, pady=10)

    def open_directory():
        """Open a directory and start scanning files."""
        directory_path = filedialog.askdirectory()
        if directory_path:
            file_paths = get_files_from_directory(directory_path)
            thread_count = int(thread_count_entry.get())  # Get user-defined thread count
            update_progress(len(file_paths))
            results, execution_time = batch_process_files(file_paths, thread_count)  # Get results and execution time
            logging.info("Scan completed.")
            generate_report(results)  # Generate a PDF report after processing

            # Update the execution time in the Tkinter interface
            execution_time_label.config(text=f"Execution Time: {execution_time:.2f} seconds")

            # Update Dash app with new results
            update_dash_results(results)

    def update_progress(total_files):
        """Update the progress bar based on the number of files scanned."""
        progress_bar['maximum'] = total_files
        for i in range(total_files):
            time.sleep(0.5)  # Simulating file processing
            progress_bar['value'] += 1
            root.update_idletasks()

    def preview_file():
        """Preview the contents of a selected file."""
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'r') as file:
                content = file.read()
                preview_text.delete(1.0, 'end')
                preview_text.insert('end', content)

    # Buttons and entries
    Button(main_frame, text="Select Directory to Scan", command=open_directory, width=30, bg="#4e169e", fg="white", font=label_font, relief="raised").grid(row=3, column=0, pady=10)
    Button(main_frame, text="Preview File", command=preview_file, width=30, bg="#4e169e", fg="white", font=label_font, relief="raised").grid(row=3, column=1, pady=10)

    Label(main_frame, text="Number of Threads (default 5):", font=label_font, bg="#178e90", fg="#dcdade").grid(row=4, column=0, pady=5)
    thread_count_entry = Entry(main_frame, font=label_font, width=10)
    thread_count_entry.insert(0, "5")  # Default thread count
    thread_count_entry.grid(row=4, column=1, pady=5)

    progress_bar = ttk.Progressbar(main_frame, orient='horizontal', mode='determinate', length=400, style="TProgressbar")
    progress_bar.grid(row=5, column=0, columnspan=2, pady=20)

    # Style for progress bar
    style = ttk.Style()
    style.configure("TProgressbar",
                    thickness=30,
                    background="#4CAF50",  # Green progress bar
                    )

    # Start the Tkinter main loop
    root.mainloop()

# Dash application for displaying scan results
app = Dash(__name__)

# Shared variable for scan results
scan_results = []

app.layout = html.Div(style={'fontFamily': 'Arial, sans-serif', 'padding': '20px'}, children=[
    html.H1("VirusTotal Directory Scanner", style={'textAlign': 'center', 'color': '#333'}),
    html.Div(id='output-data-upload', style={'margin': '10px 0'}),
    html.Div(className="table-container", children=[
        DataTable(
            id='output-table',
            columns=[
                {'name': 'File Path', 'id': 'file_path'},
                {'name': 'SHA256 Hash', 'id': 'sha256_hash'},
                {'name': 'File Size (bytes)', 'id': 'file_size'},
                {'name': 'Creation Date', 'id': 'creation_date'},
                {'name': 'Status', 'id': 'status'},
                {'name': 'Infected', 'id': 'infected'},
                {'name': 'CPU Usage (%)', 'id': 'cpu_usage'},
                {'name': 'Memory Usage (%)', 'id': 'memory_usage'}
            ],
            style_table={'overflowX': 'auto', 'border': 'thin lightgrey solid'},
            style_header={'backgroundColor': '#4CAF50', 'color': 'white', 'fontWeight': 'bold'},
            style_cell={'textAlign': 'left', 'padding': '10px', 'border': '1px solid #ddd'},
            data=[]  # Initially empty
        ),
        dcc.Loading(
            id="loading",
            children=[html.Div(id='no-data-message', style={'color': 'red', 'fontWeight': 'bold', 'textAlign': 'center', 'marginTop': '20px'})],
            type="default"
        )
    ]),
    dcc.Graph(id='pie-chart', style={'marginTop': '20px'})
])

@app.callback(
    Output('output-table', 'data'),
    Output('no-data-message', 'children'),
    Output('pie-chart', 'figure'),
    Input('output-table', 'id')  # Dummy input to trigger callback
)
def update_output(_):
    """Update the DataTable with scan results and handle no data case."""
    if scan_results:
        table_data = [{
            'file_path': file_path,
            'sha256_hash': file_hash,
            'file_size': file_size,
            'creation_date': creation_date,
            'status': status,
            'infected': "Yes" if vt_result and vt_result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0 else "No",
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent
        } for file_path, file_hash, file_size, creation_date, vt_result, status in scan_results]

        # Prepare data for the pie chart
        infected_count = sum(1 for result in scan_results if result and result[4] and result[4].get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0)
        clean_count = len(scan_results) - infected_count

        # Create pie chart data
        pie_chart_data = {
            'data': [{
                'labels': ['Infected', 'Clean'],
                'values': [infected_count, clean_count],
                'type': 'pie',
                'textinfo': 'label+percent'
            }],
            'layout': {
                'title': 'Scan Results Overview',
                'hovermode': 'closest'
            }
        }

        return table_data, "", pie_chart_data
    else:
        return [], "No scan results available.", {}

def update_dash_results(results):
    """Update the global scan_results variable with new scan data."""
    global scan_results
    scan_results = results

# Run both the Tkinter GUI and Dash app
if __name__ == "__main__":
    threading.Thread(target=start_tkinter, daemon=True).start()  # Start Tkinter in a separate thread
    app.run_server(port=8050)
    file_queue = queue.Queue()

def producer(file_paths):
    """Producteur : Ajoute des fichiers dans la queue"""
    for file_path in file_paths:
        print(f"Producteur ajoutant {file_path} dans la queue")
        file_queue.put(file_path)  # Mettre le fichier dans la queue
        time.sleep(0.1)  # Simuler le délai entre les ajouts

def consumer():
    """Consommateur : Prend les fichiers de la queue et les traite"""
    while True:
        file_path = file_queue.get()  # Récupère un fichier de la queue
        if file_path is None:  # Condition pour arrêter le consommateur
            break
        print(f"Consommateur traitant {file_path}")
        # Simuler le traitement (par exemple, scan avec VirusTotal)
        time.sleep(1)  # Simuler le temps de traitement
        file_queue.task_done()  # Indiquer que le traitement est terminé

# List of files to be processed
files_to_process = ['file1.txt', 'file2.txt', 'file3.txt', 'file4.txt']

# Démarrer les threads producteurs et consommateurs
producer_thread = threading.Thread(target=producer, args=(files_to_process,))
consumer_threads = [threading.Thread(target=consumer) for _ in range(3)]  # 3 consommateurs

# Lancer le producteur et les consommateurs
producer_thread.start()
for t in consumer_threads:
    t.start()

# Attendre que tous les threads consommateurs aient fini
producer_thread.join()
for t in consumer_threads:
    file_queue.put(None)  # Envoyer un signal de fin aux consommateurs
for t in consumer_threads:
    t.join()

print("Traitement terminé.")