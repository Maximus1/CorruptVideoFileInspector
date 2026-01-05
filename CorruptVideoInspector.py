# pylint: disable=line-too-long, missing-function-docstring, missing-class-docstring, missing-module-docstring
import csv
import os
import re
import subprocess
import tkinter as tk
import platform
import shutil
import time
from threading import Thread
from tkinter import filedialog
from tkinter import ttk
from tkinter import messagebox
from datetime import datetime

import psutil

if 'Darwin' in platform.system():
    try:
        from tkmacosx import Button as MacButton
    except ImportError:
        MacButton = tk.Button
else:
    MacButton = tk.Button

VIDEO_EXTENSIONS = ['.mp4', '.avi', '.mov', '.wmv', '.mkv', '.flv', '.webm', '.m4v', '.m4p', '.mpeg', '.mpg', '.3gp', '.3g2']

# ========================== CLASSES ===========================

class VideoObject():
    def __init__(self, filename, full_filepath):
        self.filename = filename
        self.full_filepath = full_filepath

# ========================= FUNCTIONS ==========================

def clear_window(root):
    for widget in root.winfo_children():
        widget.destroy()

def show_initial_ui(root):
    clear_window(root)
    label_select_directory = tk.Label(root, wraplength=450, justify="left", text="Select a directory to search for all video files within the chosen directory and all of its containing subdirectories", font=('Helvetica', 16))
    label_select_directory.pack(fill=tk.X, pady=20, padx=20)

    button_select_directory = tk.Button(root, text="Select Directory", width=20, command=lambda: selectDirectory(root))
    button_select_directory.pack(pady=20)

def apply_listbox_read_only_bindings(listbox):
    listbox.bind('<<ListboxSelect>>', lambda e: "break")
    listbox.bind('<Button-1>', lambda e: "break")
    listbox.bind('<Button-2>', lambda e: "break")
    listbox.bind('<Button-3>', lambda e: "break")
    listbox.bind('<ButtonRelease-1>', lambda e: "break")
    listbox.bind('<Double-1>', lambda e: "break")
    listbox.bind('<Double-Button-1>', lambda e: "break")
    listbox.bind('<B1-Motion>', lambda e: "break")

def is_mac_os():
    if 'Darwin' in platform.system():
        return True
    return False

def is_windows_os():
    if 'Windows' in platform.system():
        return True
    return False

def is_linux_os():
    if 'Linux' in platform.system():
        return True
    return False

def get_ffmpeg_path():
    if is_mac_os():
        return './ffmpeg'
    elif is_windows_os():
        return os.path.abspath(os.path.join(os.path.dirname(__file__), 'ffmpeg.exe'))
    elif is_linux_os():
        return shutil.which('ffmpeg')
    return None

def check_ffmpeg_exists():
    path = get_ffmpeg_path()
    if path and os.path.exists(path):
        return True
    return False

def selectDirectory(root):
    directory = filedialog.askdirectory()

    if len(directory) > 0:
        afterDirectoryChosen(root, directory)


def convertTime(seconds):
    seconds = seconds % (24 * 3600)
    hour = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60
    return "%d:%02d:%02d" % (hour, minutes, seconds)

def truncateFilename(input):
    file_name, file_extension = os.path.splitext(input)
    if is_mac_os() and len(file_name) > 50:
        truncated_string = file_name[0:49]
        return f'{truncated_string}..{file_extension}'
    elif is_windows_os() and len(file_name) > 42:
        truncated_string = file_name[0:41]
        return f'{truncated_string}..{file_extension}'
    else:
        return input

def find_all_videos(dir):
    videos_found_list = []
    for root, dirs, files in os.walk(dir):
        for file in files:
            if file.lower().endswith(tuple(VIDEO_EXTENSIONS)):
                video_obj = VideoObject(file, os.path.join(root, file))
                videos_found_list.append(video_obj)
    videos_found_list.sort(key=lambda x: x.filename)
    return videos_found_list

def countAllVideoFiles(video_list):
    return len(video_list)

def getAllVideoFiles(video_list):
    sorted_videos_list = []
    index = 1
    for video in video_list:
        sorted_videos_list.append(f' {index}:  {video.filename}')
        index += 1
    return sorted_videos_list

def verify_ffmpeg_still_running():
    global g_cpu_status
    global g_cached_proc
    global g_ffmpeg_pid

    cpu_usage = 0.0
    found = False
    output = "CPU: ---"
    num_cores = psutil.cpu_count() or 1

    if g_ffmpeg_pid:
        try:
            if not g_cached_proc or g_cached_proc.pid != g_ffmpeg_pid:
                g_cached_proc = psutil.Process(g_ffmpeg_pid)

            if g_cached_proc.is_running() and "ffmpeg" in g_cached_proc.name().lower():
                raw_cpu = g_cached_proc.cpu_percent(interval=None)
                cpu_usage = round(raw_cpu / num_cores, 1)
                output = f"CPU: {cpu_usage}% (ffmpeg)"
                found = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            g_cached_proc = None

    if not found:
        # Fallback: Suche alle ffmpeg Prozesse, aber nur die aus unserem Verzeichnis
        ffmpeg_path = get_ffmpeg_path()
        for proc in psutil.process_iter(['name', 'exe']):
            try:
                if "ffmpeg" in proc.info['name'].lower():
                    # Prüfe ob es "unser" ffmpeg ist (falls möglich)
                    if ffmpeg_path and proc.info['exe'] and os.path.normpath(proc.info['exe']) == os.path.normpath(ffmpeg_path):
                        raw_cpu = proc.cpu_percent(interval=0.1)
                        cpu_usage = round(raw_cpu / num_cores, 1)
                        if cpu_usage > 0:
                            output = f"CPU: {cpu_usage}% (ffmpeg)"
                            found = True
                            break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    if not found:
        output = "CPU: ---"

    g_cpu_status.set(output)

def kill_ffmpeg_warning(root, log_file):
    ffmpeg_kill_window = tk.Toplevel(root)
    ffmpeg_kill_window.resizable(False, False)
    if is_mac_os():
        ffmpeg_kill_window.geometry("400x300")
    elif is_windows_os():
        ffmpeg_kill_window.geometry("400x400")
    elif is_linux_os():
        ffmpeg_kill_window.geometry("400x400")
    ffmpeg_kill_window.title("Safely Quit Program")

    label_ffmpeg_kill = tk.Label(ffmpeg_kill_window, wraplength=375, width=375, text="This application spawns a subprocess named 'ffmpeg'. Clicking the button below will terminate the 'ffmpeg' subprocess and safely quit the application. This will prematurely end all video processing.", font=('Helvetica', 14))
    label_ffmpeg_kill.pack(fill=tk.X, pady=20)

    button_kill_ffmpeg = tk.Button(ffmpeg_kill_window, background='#E34234', foreground='white', text="Terminate Program", width=25, command=lambda: kill_ffmpeg(root, log_file))
    button_kill_ffmpeg.pack(pady=10)

def kill_ffmpeg(root, log_file):
    log_file.write(f'---USER MANUALLY TERMINATED PROGRAM---\n')
    log_file.flush()

    global g_ffmpeg_pid
    terminated = False

    if g_ffmpeg_pid:
        try:
            parent = psutil.Process(g_ffmpeg_pid)
            for child in parent.children(recursive=True):
                child.kill()
            parent.kill()
            terminated = True
        except psutil.NoSuchProcess:
            # Prozess bereits beendet, alles ok
            terminated = True
        except psutil.AccessDenied as e:
            log_file.write(f'Could not kill via PID {g_ffmpeg_pid}: {e}\n')

    if not terminated:
        # Fallback: Nur ffmpeg Prozesse aus unserem Verzeichnis beenden
        ffmpeg_path = get_ffmpeg_path()
        for proc in psutil.process_iter(['name', 'exe']):
            try:
                if "ffmpeg" in proc.info['name'].lower():
                    # Nur killen, wenn es exakt unser Binary ist
                    if ffmpeg_path and proc.info['exe'] and os.path.normpath(proc.info['exe']) == os.path.normpath(ffmpeg_path):
                        proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    # Beende das Hauptprogramm
    os._exit(0)


def estimatedTime(total_videos):
    # estimating 3 mins per 2GB video file, on average
    total_minutes = total_videos * 3
    # Get hours with floor division
    hours = total_minutes // 60
    # Get additional minutes with modulus
    minutes = total_minutes % 60
    # Create time as a string
    time_string = "{} hours, {} minutes".format(hours, minutes)
    return time_string


def calculate_progress(count, total):
    return "{0}%".format(int((count / total) * 100))

def inspect_video_files(directory, video_list, tkinter_window, listbox_completed_videos, index_start, log_file, progress_bar, button_kill_ffmpeg):
    try:
        global g_count
        global g_currently_processing

        log_file.write('CREATED: _Logs.log\n')
        log_file.write('CREATED: _Results.csv\n')
        log_file.write('=================================================================\n')
        log_file.flush()

        # CSV Results file
        results_file_path = os.path.join(directory, '_Results.csv')
        results_file_exists = os.path.isfile(results_file_path)
        if results_file_exists:
            os.remove(results_file_path)

        results_file = open(results_file_path, 'a+', encoding="utf8", newline='')
        results_file_writer = csv.writer(results_file)

        header = ['Video File', 'Corrupted']
        results_file_writer.writerow(header)
        results_file.flush()

        totalVideoFiles = len(video_list)
        start_time = datetime.now().strftime('%Y-%m-%d %I:%M %p')

        log_file.write(f'DIRECTORY: {directory}\n')
        log_file.write(f'TOTAL VIDEO FILES FOUND: {totalVideoFiles}\n')
        log_file.write(f'STARTING FROM VIDEO INDEX: {index_start}\n')
        log_file.write(f'START TIME: {start_time}\n')
        log_file.write('=================================================================\n')
        log_file.write('(DURATION IS IN HOURS:MINUTES:SECONDS)\n')
        log_file.flush()

        count = 0
        processed_count = 0
        for video in video_list:
            if index_start > count + 1:
                count += 1
                continue

            def update_listbox_processing(idx=count):
                listbox_completed_videos.itemconfig(idx, bg='yellow')
                listbox_completed_videos.see(idx)
            tkinter_window.after(0, update_listbox_processing)

            start_time = time.time()

            global g_progress
            g_progress.set(calculate_progress(count, totalVideoFiles))

            g_count.set(f"{count + 1} / {totalVideoFiles}")

            g_currently_processing.set(truncateFilename(video.filename))

            proc = None
            ffmpeg_path = get_ffmpeg_path()
            global g_ffmpeg_pid
            global g_ffmpeg_pid_var

            duration_str = "00:00:00"
            try:
                dur_cmd = [ffmpeg_path, '-i', video.full_filepath]
                dur_kwargs = {}
                if is_windows_os():
                    dur_kwargs['creationflags'] = 0x08000000
                dur_proc = subprocess.Popen(dur_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace', **dur_kwargs)
                _, dur_err = dur_proc.communicate()
                dur_match = re.search(r"Duration:\s*(\d{2}:\d{2}:\d{2})", dur_err)
                if dur_match:
                    duration_str = dur_match.group(1)
            except Exception:
                pass
            
            cmd = [ffmpeg_path, '-v', 'error', '-progress', 'pipe:1', '-i', video.full_filepath, '-f', 'null', '-']
            
            popen_kwargs = {}
            if is_windows_os():
                popen_kwargs['creationflags'] = 0x08000000
            
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace', **popen_kwargs)
            g_ffmpeg_pid = proc.pid
            g_ffmpeg_pid_var.set(f"FFMPEG PID: {g_ffmpeg_pid}")

            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                if "out_time=" in line:
                    time_str = line.split('=')[1].strip().split('.')[0]
                    g_currently_processing.set(f"Current File Progress ({time_str} / {duration_str})")

            output, error = proc.communicate()
            return_code = proc.returncode

            # Debug
            print(f'return_code= {return_code}\n')

            # Eine Datei gilt als korrupt, wenn der Return-Code ungleich 0 ist
            # oder Fehlermeldungen in stderr/stdout ausgegeben wurden (bei -v error)
            is_corrupt = (return_code != 0) or (output and output.strip()) or (error and error.strip())

            elapsed_time = time.time() - start_time
            readable_time = convertTime(elapsed_time)
            row = ''
            if not is_corrupt:
                # Healthy
                print("\033[92m{0}\033[00m".format("HEALTHY -> {}".format(video.filename)), end='\n')  # green

                log_file.write('=================================================================\n')
                log_file.write(f'{video.filename}\n')
                log_file.write('STATUS: ✓ HEALTHY ✓\n')
                log_file.write(f'DURATION: {readable_time}\n')
                log_file.flush()

                row = [video.filename, 0]
                def update_listbox_healthy(idx=count):
                    listbox_completed_videos.itemconfig(idx, bg='green')
                    listbox_completed_videos.see(idx)
                tkinter_window.after(0, update_listbox_healthy)
            else:
                # Corrupt
                print("\033[31m{0}\033[00m".format("CORRUPTED -> {}".format(video.filename)), end='\n')  # red

                log_file.write('=================================================================\n')
                log_file.write(f'{video.filename}\n')
                log_file.write('STATUS: X CORRUPT X\n')
                log_file.write(f'DURATION: {readable_time}\n')
                log_file.flush()

                row = [video.filename, 1]
                def update_listbox_corrupt(idx=count):
                    listbox_completed_videos.itemconfig(idx, bg='red')
                    listbox_completed_videos.see(idx)
                tkinter_window.after(0, update_listbox_corrupt)

            results_file_writer.writerow(row)
            results_file.flush()

            count += 1
            processed_count += 1

            g_progress.set(calculate_progress(count, totalVideoFiles))

        g_count.set("---")
        g_currently_processing.set("N/A")
        g_ffmpeg_pid_var.set("FFMPEG PID: ---")
        def finish_ui():
            progress_bar.stop()
            progress_bar['value'] = 100
            # Button Swap: Safely Quit -> Restart
            if button_kill_ffmpeg:
                button_kill_ffmpeg.destroy()

            button_restart = tk.Button(tkinter_window, text="Restart", width=25, command=lambda: show_initial_ui(tkinter_window))
            button_restart.pack(pady=10)

        tkinter_window.after(0, finish_ui)

        results_file.flush()
        results_file.close()

        end_time = datetime.now().strftime('%Y-%m-%d %I:%M %p')

        print(f'Finished: {end_time}')
        log_file.write('=================================================================\n')
        log_file.write(f'SUCCESSFULLY PROCESSED {(totalVideoFiles + 1) - index_start} VIDEO FILES\n')
        log_file.write(f'END TIME: {end_time}\n')
        log_file.write('=================================================================\n')
        log_file.flush()
        log_file.close()
    except Exception as e:
        log_file.write(f'ERROR in "inspect_video_files" (aka main thread): {e}\n')
        log_file.flush()

def start_program(directory, video_list, root, index_start, log_file):
    try:
        clear_window(root)

        progress_frame = tk.Frame(root)
        progress_frame.pack(pady=10)

        label_progress_text = tk.Label(progress_frame, text="Progress:", font=('Helvetica Bold', 30))
        label_progress_text.pack(side=tk.LEFT, padx=(0, 10))

        g_progress.set("0%")
        label_progress_var = tk.Label(progress_frame, textvariable=g_progress, font=('Helvetica Bold', 30))
        label_progress_var.pack(side=tk.LEFT)

        progress_bar = ttk.Progressbar(root, orient="horizontal", mode="indeterminate", length=300)
        progress_bar.pack(pady=(0, 20))
        progress_bar.start()

        label_currently_processing_text = tk.Label(root, text="Currently Processing:", font=('Helvetica Bold', 18))
        label_currently_processing_text.pack(fill=tk.X, pady=10)

        g_count.set("0 / 0")
        label_count_var = tk.Label(root, textvariable=g_count, font=('Helvetica', 16))
        label_count_var.pack(fill=tk.X, pady=(0, 10))

        g_currently_processing.set("N/A")
        label_currently_processing_var = tk.Label(root, textvariable=g_currently_processing, font=('Helvetica', 16))
        label_currently_processing_var.pack(fill=tk.X, pady=(0, 10))

        frame_listbox = tk.Frame(root)
        frame_listbox.pack(expand=False, fill=tk.BOTH, side=tk.TOP, padx=10, pady=10)

        scrollbar = tk.Scrollbar(frame_listbox)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        listbox_completed_videos = tk.Listbox(frame_listbox, font=('Helvetica', 16), yscrollcommand=scrollbar.set)
        listbox_completed_videos.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=listbox_completed_videos.yview)

        apply_listbox_read_only_bindings(listbox_completed_videos)

        for i, video in enumerate(video_list):
            listbox_completed_videos.insert(tk.END, f' {video.filename}')
            listbox_completed_videos.itemconfig(i, bg='#d3d3d3')

        if is_mac_os():
            # https://stackoverflow.com/questions/1529847/how-to-change-the-foreground-or-background-colour-of-a-tkinter-button-on-mac-os
            button_kill_ffmpeg = MacButton(root, background='#E34234', borderless=1, foreground='white', text="Safely Quit", width=500, command=lambda: kill_ffmpeg_warning(root, log_file))
            button_kill_ffmpeg.pack(pady=(10, 5))
        elif is_windows_os():
            button_kill_ffmpeg = tk.Button(root, background='#E34234', foreground='white', text="Safely Quit", width=25, command=lambda: kill_ffmpeg_warning(root, log_file))
            button_kill_ffmpeg.pack(pady=(10, 5))
        elif is_linux_os():
            button_kill_ffmpeg = tk.Button(root, background='#E34234', foreground='white', text="Safely Quit", width=25, command=lambda: kill_ffmpeg_warning(root, log_file))
            button_kill_ffmpeg.pack(pady=(10, 5))

        g_cpu_status.set("CPU: ---")
        label_cpu_status = tk.Label(root, textvariable=g_cpu_status, font=('Helvetica Bold', 12))
        label_cpu_status.pack(pady=(0, 5))

        g_ffmpeg_pid_var.set("FFMPEG PID: ---")
        label_ffmpeg_pid = tk.Label(root, textvariable=g_ffmpeg_pid_var, font=('Helvetica', 10))
        label_ffmpeg_pid.pack(pady=(0, 10))

        # Automatisches Update des CPU-Status alle 1 Sekunde starten
        def auto_update_cpu():
            if thread.is_alive():
                verify_ffmpeg_still_running()
                root.after(1000, auto_update_cpu)
            else:
                g_cpu_status.set("CPU: Finished")

        thread = Thread(target=inspect_video_files, args=(directory, video_list, root, listbox_completed_videos, index_start, log_file, progress_bar, button_kill_ffmpeg))
        thread.start()

        # CPU Update verzögert starten
        root.after(2000, auto_update_cpu)
    except Exception as e:
        log_file.write(f'ERROR in "start_program": {e}\n')
        log_file.flush()

def afterDirectoryChosen(root, directory):
    if not check_ffmpeg_exists():
        messagebox.showerror("FFmpeg Missing", "The FFmpeg binary was not found in the application directory. Please ensure 'ffmpeg' (macOS) or 'ffmpeg.exe' (Windows) is present.")
        show_initial_ui(root)
        return

    clear_window(root)
    # Log file
    log_file_path = os.path.join(directory, '_Logs.log')
    log_file_exists = os.path.isfile(log_file_path)
    if log_file_exists:
        os.remove(log_file_path)
    log_file = open(log_file_path, 'a', encoding="utf8")

    # Logging
    print('CORRUPT VIDEO FILE INSPECTOR')
    print('')
    log_file.write('=================================================================\n')
    log_file.write('                CORRUPT VIDEO FILE INSPECTOR\n')
    log_file.write('=================================================================\n')
    log_file.flush()

    video_list = find_all_videos(directory)
    totalVideos = len(video_list)

    label_chosen_directory = tk.Label(root, text="Chosen directory:", font=('Helvetica Bold', 18))
    label_chosen_directory.pack(fill=tk.X, pady=5)
    label_chosen_directory_var = tk.Label(root, wraplength=450, text=f"{directory}", font=('Helvetica', 14))
    label_chosen_directory_var.pack(fill=tk.X, pady=(5, 20))

    label_video_count = tk.Label(root, text="Total number of videos found:", font=('Helvetica Bold', 18))
    label_video_count.pack(fill=tk.X, pady=5)
    label_video_count_var = tk.Label(root, text=f"{totalVideos}", font=('Helvetica', 16))
    label_video_count_var.pack(fill=tk.X, pady=(5, 20))

    frame_listbox = tk.Frame(root)
    frame_listbox.pack(padx=10, fill=tk.BOTH, expand=False)

    scrollbar = tk.Scrollbar(frame_listbox)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    listbox_videos_found_with_index = tk.Listbox(frame_listbox, font=('Helvetica', 16), width=480, yscrollcommand=scrollbar.set)
    listbox_videos_found_with_index.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.config(command=listbox_videos_found_with_index.yview)

    apply_listbox_read_only_bindings(listbox_videos_found_with_index)

    all_videos_found_formatted = getAllVideoFiles(video_list)
    for video in all_videos_found_formatted:
        listbox_videos_found_with_index.insert(tk.END, video)
    root.update()

    label_index_start = tk.Label(root,
                                 text=f"Start at video index (1 - {totalVideos}):",
                                 font=('Helvetica Bold', 18))
    label_index_start.pack(fill=tk.X, pady=5)

    entry_index_input = tk.Entry(root, width=50)
    entry_index_input.focus_set()
    entry_index_input.insert(tk.END, '1')
    entry_index_input.pack(fill=tk.X, padx=200)

    label_explanation = tk.Label(root, wraplength=450,
                                 text="The default is '1'. Set index to '1' if you want to start from the beginning and process all videos. If you are resuming a previous operation, then set the index to the desired number. Also note, each run will overwrite the _Logs and _Results files.",
                                 font=('Helvetica Italic', 12))
    label_explanation.pack(fill=tk.X, pady=5, padx=20)

    if totalVideos > 0:
        button_start = tk.Button(root, text="Start Inspecting", width=25, command=lambda: start_program(directory, video_list, root, int(entry_index_input.get()), log_file))
        button_start.pack(pady=20)
    else:
        root.withdraw()
        error_window = tk.Toplevel(root)
        error_window.resizable(False, False)
        error_window.geometry("400x200")
        error_window.title("Error")

        label_error_msg = tk.Label(error_window, width=375, text="No video files found in selected directory!", font=('Helvetica', 14))
        label_error_msg.pack(fill=tk.X, pady=20)

        button_exit = tk.Button(error_window, text="Exit", width=30, command=lambda: exit())
        button_exit.pack()

# ========================= MAIN ==========================

root = tk.Tk()
root.title("Corrupt Video Inspector")
if is_mac_os():
    root.geometry("500x650")
if is_windows_os():
    root.geometry("500x750")
    icon_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'icon.ico'))
    root.iconbitmap(default=icon_path)
if is_linux_os():
    root.geometry("500x750")
g_progress = tk.StringVar()
g_count = tk.StringVar()
g_currently_processing = tk.StringVar()
g_cpu_status = tk.StringVar()
g_ffmpeg_pid_var = tk.StringVar()
g_cached_proc = None
g_ffmpeg_pid = None

show_initial_ui(root)

root.mainloop()
