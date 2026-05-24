import customtkinter as cstk
from tkinter import filedialog
import subprocess
import os
import time
import sys

cstk.set_appearance_mode("dark")
cstk.set_default_color_theme("blue")

root = cstk.CTk()
root.title("GuardAntivirusMonitor")
root.geometry("640x570")
root.resizable(False, False)

def get_backend_path():
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, "GuardAntivirusMonitor.exe")

exe_file = get_backend_path()
active_pid = None
all_procs = []

def load_icon():
    if getattr(sys, 'frozen', False):
        icon_path = os.path.join(sys._MEIPASS, "icon.ico")
    else:
        icon_path = "icon.ico"
    if os.path.exists(icon_path):
        root.iconbitmap(icon_path)

root.after(10, load_icon)

def refresh_list():
    global active_pid, all_procs
    active_pid = None
    btn_kill.configure(state="disabled", text="Select a process from the list")
    search_bar.delete(0, "end")
    
    if os.path.exists(exe_file):
        subprocess.run([exe_file])
    else:
        label_status.configure(text="CRITICAL ERROR: Backend not found!", text_color="#FF3333")
        return

    all_procs.clear()
    total = 0

    if os.path.exists("processes.txt"):
        f = open("processes.txt", "r", encoding="utf-8")
        for line in f:
            if ";" in line:
                parts = line.replace("\n", "").split(";")
                if len(parts) == 3:
                    pid = parts[0]
                    name = parts[1]
                    status = parts[2]
                    total = total + 1
                    all_procs.append((pid, name, status))
        f.close()
        
        search_proc()
        label_total.configure(text="Total: " + str(total) + "  |  Threats: 0")
        label_status.configure(text="Process list loaded. Use scanning modules below.", text_color="#00ADB5")

def search_proc(*args):
    for widget in scroll_box.winfo_children():
        widget.destroy()
        
    user_input = search_bar.get().lower()
    
    for pid, name, status in all_procs:
        if user_input in name.lower() or user_input in pid:
            add_new_row(pid, name, status)

def scan_sys():
    btn_scan.configure(state="disabled")
    btn_refresh.configure(state="disabled")
    btn_file.configure(state="disabled")
    search_bar.configure(state="disabled")
    label_status.configure(text="Scanning system memory modules...", text_color="orange")
    
    bar.set(0)
    bar.pack(pady=5, padx=20, fill="x")
    
    for i in range(1, 101):
        time.sleep(0.01)
        bar.set(i / 100)
        root.update_idletasks()

    for widget in scroll_box.winfo_children():
        widget.destroy()

    malware_count = 0
    user_input = search_bar.get().lower()
    
    for pid, name, status in all_procs:
        if status == "VIRUS":
            malware_count = malware_count + 1
        if user_input in name.lower() or user_input in pid:
            add_new_row(pid, name, status)

    label_total.configure(text="Total: " + str(len(all_procs)) + "  |  Threats: " + str(malware_count))
    bar.pack_forget()
    btn_scan.configure(state="normal")
    btn_refresh.configure(state="normal")
    btn_file.configure(state="normal")
    search_bar.configure(state="normal")

    if malware_count > 0:
        label_status.configure(text="THREATS DETECTED: " + str(malware_count) + " found!", text_color="red")
    else:
        label_status.configure(text="Scan complete. No threats found.", text_color="green")

def file_btn():
    file_path = filedialog.askopenfilename(title="Select file for verification")
    if file_path == "":
        return
        
    file_name = os.path.basename(file_path)
    label_status.configure(text="Verifying file " + file_name, text_color="orange")
    
    if os.path.exists(exe_file):
        res = subprocess.run([exe_file, "--check", file_path])
        if res.returncode == 666:
            label_status.configure(text="ALERT: File " + file_name + " is malware!", text_color="red")
        elif res.returncode == 200:
            label_status.configure(text="File " + file_name + " is clean.", text_color="green")
        else:
            label_status.configure(text="Failed to open file.", text_color="orange")

def row_click(pid, name):
    global active_pid
    active_pid = pid
    btn_kill.configure(state="normal", text="TERMINATE PROCESS (PID: " + str(pid) + ")")

def add_new_row(pid, name, status):
    if status == "VIRUS":
        txt = " ❌  [" + str(pid) + "] " + name + "  -->  MALWARE!"
        color = "red"
        hov = "#4A1515"
    else:
        txt = " 📄  [" + str(pid) + "] " + name
        color = "white"
        hov = "#252A34"

    row_btn = cstk.CTkButton(
        scroll_box, 
        text=txt, 
        anchor="w",
        font=("Segoe UI", 13),
        fg_color="transparent",
        text_color=color,
        hover_color=hov,
        height=32,
        corner_radius=6,
        command=lambda: row_click(pid, name)
    )
    row_btn.pack(fill="x", padx=8, pady=3)

def kill_proc():
    global active_pid
    if active_pid != None:
        res = subprocess.run([exe_file, "--kill", str(active_pid)])
        if res.returncode == 100:
            label_status.configure(text=f"Successfully terminated process {active_pid}", text_color="green")
        else:
            label_status.configure(text="Error: Access Denied", text_color="orange")
        root.after(1000, refresh_list)

frame_top = cstk.CTkFrame(root, fg_color="#1A1C23", height=70, corner_radius=0)
frame_top.pack(fill="x", side="top")

title = cstk.CTkLabel(frame_top, text="GuardAntivirusMonitor", font=("Segoe UI", 22, "bold"), text_color="#00ADB5")
title.pack(side="left", padx=20, pady=15)

label_total = cstk.CTkLabel(frame_top, text="Total: 0  |  Threats: 0", font=("Segoe UI Semibold", 13), text_color="#8E929A")
label_total.pack(side="right", padx=20, pady=15)

frame_main = cstk.CTkFrame(root, fg_color="#111318", corner_radius=0)
frame_main.pack(fill="both", expand=True, padx=0, pady=0)

frame_search = cstk.CTkFrame(frame_main, fg_color="transparent")
frame_search.pack(fill="x", padx=20, pady=(10, 0))

search_bar = cstk.CTkEntry(
    frame_search, 
    placeholder_text="🔍 Enter name or PID to filter...", 
    font=("Segoe UI", 12),
    height=35,
    border_color="#222831",
    corner_radius=8
)
search_bar.pack(fill="x")
search_bar.bind("<KeyRelease>", search_proc)

scroll_box = cstk.CTkScrollableFrame(
    frame_main, 
    fg_color="#161920", 
    border_color="#222831", 
    border_width=1,
    corner_radius=12
)
scroll_box.pack(padx=20, pady=(10, 15), fill="both", expand=True)

frame_bottom = cstk.CTkFrame(root, fg_color="#1A1C23", height=180, corner_radius=0)
frame_bottom.pack(fill="x", side="bottom")

btn_kill = cstk.CTkButton(
    frame_bottom, 
    text="Select a process from the list", 
    state="disabled", 
    font=("Segoe UI Semibold", 14),
    fg_color="#D63031", 
    hover_color="#E17055", 
    text_color_disabled="#57606F", 
    height=42,
    corner_radius=8
)
btn_kill.configure(command=kill_proc)
btn_kill.pack(pady=(10, 5), fill="x", padx=20)

frame_btns = cstk.CTkFrame(frame_bottom, fg_color="transparent")
frame_btns.pack(fill="x", padx=20, pady=2)

btn_refresh = cstk.CTkButton(
    frame_btns, 
    text="🔄  REFRESH LIST", 
    font=("Segoe UI Semibold", 11),
    fg_color="#222831",
    hover_color="#393E46",
    text_color="#00ADB5",
    height=32,
    corner_radius=8,
    command=refresh_list
)
btn_refresh.pack(side="left", expand=True, fill="x", padx=(0, 3))

btn_scan = cstk.CTkButton(
    frame_btns, 
    text="🛡️  SYSTEM SCAN", 
    font=("Segoe UI Semibold", 11),
    fg_color="#222831",
    hover_color="#393E46",
    text_color="#00ADB5",
    height=32,
    corner_radius=8,
    command=scan_sys
)
btn_scan.pack(side="left", expand=True, fill="x", padx=3)

btn_file = cstk.CTkButton(
    frame_btns, 
    text="📂  FILE SCAN", 
    font=("Segoe UI Semibold", 11),
    fg_color="#00ADB5",
    hover_color="#008085",
    text_color="white",
    height=32,
    corner_radius=8,
    command=file_btn
)
btn_file.pack(side="right", expand=True, fill="x", padx=(3, 0))

bar = cstk.CTkProgressBar(frame_bottom, orientation="horizontal", height=4, progress_color="#00ADB5")

frame_status_bar = cstk.CTkFrame(frame_bottom, fg_color="transparent")
frame_status_bar.pack(fill="x", padx=20, pady=(5, 10))

label_avtor = cstk.CTkLabel(
    frame_status_bar, 
    text="© Created by Sad-Merezha", 
    font=("Segoe UI Semibold", 11), 
    text_color="#8E929A"
)
label_avtor.pack(side="left")

label_status = cstk.CTkLabel(frame_status_bar, text="Initializing modules...", font=("Segoe UI Semibold", 12), text_color="#00ADB5")
label_status.pack(side="right", expand=True, anchor="center", padx=(0, 130))

root.after(500, refresh_list)
root.mainloop()
