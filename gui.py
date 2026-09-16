import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import subprocess
import sys
import threading
import os
import tempfile

try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

class ArxmlSecDiffGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ARXML SecDiff")
        self.root.geometry("800x650")

        self.before_files = []
        self.updated_files = []
        self.roles_file = ""
        self.graph_dir = ""

        self.create_widgets()

    def create_widgets(self):
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(5, weight=1)

        # Before Files
        tk.Label(self.root, text="Before ARXML Files:").grid(row=0, column=0, sticky="e", padx=10, pady=5)
        self.before_entry = tk.Entry(self.root)
        self.before_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        tk.Button(self.root, text="Browse", command=self.browse_before).grid(row=0, column=2, sticky="w", padx=5, pady=5)

        # Updated Files
        tk.Label(self.root, text="Updated ARXML Files:").grid(row=1, column=0, sticky="e", padx=10, pady=5)
        self.updated_entry = tk.Entry(self.root)
        self.updated_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=5)
        tk.Button(self.root, text="Browse", command=self.browse_updated).grid(row=1, column=2, sticky="w", padx=5, pady=5)

        # Roles YAML
        tk.Label(self.root, text="Roles YAML (Optional):").grid(row=2, column=0, sticky="e", padx=10, pady=5)
        self.roles_entry = tk.Entry(self.root)
        self.roles_entry.grid(row=2, column=1, sticky="ew", padx=5, pady=5)
        tk.Button(self.root, text="Browse", command=self.browse_roles).grid(row=2, column=2, sticky="w", padx=5, pady=5)

        # Button Frame
        self.btn_frame = tk.Frame(self.root)
        self.btn_frame.grid(row=3, column=0, columnspan=3, pady=15)

        # Run Button
        self.run_button = tk.Button(self.btn_frame, text="Run Analysis", command=self.run_analysis, bg="green", fg="white", width=15)
        self.run_button.pack(side=tk.LEFT, padx=10)

        # View Graph Button
        self.graph_button = tk.Button(self.btn_frame, text="View Graphs in Browser", command=self.view_graphs, state=tk.DISABLED, width=20)
        self.graph_button.pack(side=tk.LEFT, padx=10)

        # Output Text
        tk.Label(self.root, text="Output:").grid(row=4, column=0, sticky="nw", padx=10)
        self.output_text = scrolledtext.ScrolledText(self.root, font=("Consolas", 10))
        self.output_text.grid(row=5, column=0, columnspan=3, sticky="nsew", padx=10, pady=5)

    def browse_before(self):
        files = filedialog.askopenfilenames(title="Select Before ARXML Files", filetypes=[("ARXML Files", "*.arxml"), ("All Files", "*.*")])
        if files:
            self.before_files = list(files)
            self.before_entry.delete(0, tk.END)
            self.before_entry.insert(0, "; ".join(self.before_files))

    def browse_updated(self):
        files = filedialog.askopenfilenames(title="Select Updated ARXML Files", filetypes=[("ARXML Files", "*.arxml"), ("All Files", "*.*")])
        if files:
            self.updated_files = list(files)
            self.updated_entry.delete(0, tk.END)
            self.updated_entry.insert(0, "; ".join(self.updated_files))

    def browse_roles(self):
        file = filedialog.askopenfilename(title="Select Roles YAML File", filetypes=[("YAML Files", "*.yaml;*.yml"), ("All Files", "*.*")])
        if file:
            self.roles_file = file
            self.roles_entry.delete(0, tk.END)
            self.roles_entry.insert(0, self.roles_file)

    def run_analysis(self):
        if not self.before_files:
            messagebox.showerror("Error", "Please select at least one 'Before' ARXML file.")
            return
        if not self.updated_files:
            messagebox.showerror("Error", "Please select at least one 'Updated' ARXML file.")
            return

        self.run_button.config(state=tk.DISABLED, text="Running...")
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, "Starting analysis...\n\n")

        # Run in a separate thread to keep UI responsive
        threading.Thread(target=self._execute_cli, daemon=True).start()

    def _execute_cli(self):
        cmd = [sys.executable, "-m", "arxml_secdiff.cli", "--verbose"]
        
        cmd.extend(["--before"])
        cmd.extend(self.before_files)
        
        cmd.extend(["--updated"])
        cmd.extend(self.updated_files)

        if self.roles_file:
            cmd.extend(["--roles", self.roles_file])

        # Create a temp directory for graphs
        self.graph_dir = tempfile.mkdtemp(prefix="arxml_graphs_")
        cmd.extend(["--export-graphs", self.graph_dir])

        try:
            # Set cwd to the script directory to ensure module is found if running from source
            cwd = os.path.dirname(os.path.abspath(__file__))
            process = subprocess.Popen(
                cmd, 
                cwd=cwd,
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True,
                encoding="utf-8",
                errors="replace"
            )
            
            for line in process.stdout:
                self.root.after(0, self._append_output, line)

            process.wait()
            self.root.after(0, self._append_output, f"\nProcess finished with exit code {process.returncode}")

            # Check if graphs were generated
            updated_graph_path = os.path.join(self.graph_dir, "updated_graph.png")
            if os.path.exists(updated_graph_path):
                self.root.after(0, lambda: self.graph_button.config(state=tk.NORMAL))

        except Exception as e:
            self.root.after(0, self._append_output, f"\nError executing command: {e}")
        
        finally:
            self.root.after(0, self._reset_run_button)

    def view_graphs(self):
        before_path = os.path.join(self.graph_dir, "before_graph.png")
        updated_path = os.path.join(self.graph_dir, "updated_graph.png")
        if not os.path.exists(updated_path) or not os.path.exists(before_path):
            messagebox.showerror("Error", "Graph images not found! The analysis might have failed.")
            return

        # Generate a simple HTML page to show both graphs linked side by side
        html_path = os.path.join(self.graph_dir, "view_graphs.html")
        html_content = f"""<!DOCTYPE html>
        <html>
        <head>
            <title>ARXML SecDiff Graphs</title>
            <style>
                body {{ font-family: sans-serif; background: #f5f5f5; padding: 20px; }}
                .container {{ display: flex; flex-direction: column; align-items: center; gap: 40px; }}
                .graph-container {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 100%; max-width: 1400px; text-align: center; }}
                img {{ max-width: 100%; height: auto; border: 1px solid #ddd; }}
                h2 {{ color: #333; }}
                p {{ color: #666; font-size: 0.9em; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="graph-container">
                    <h2>Updated Architecture</h2>
                    <p><i>Highlighted edges indicate paths an attacker can newly traverse. Click image to open directly.</i></p>
                    <a href="file:///{updated_path.replace(chr(92), '/')}"><img src="file:///{updated_path.replace(chr(92), '/')}"></a>
                </div>
                <div class="graph-container">
                    <h2>Before Architecture</h2>
                    <a href="file:///{before_path.replace(chr(92), '/')}"><img src="file:///{before_path.replace(chr(92), '/')}"></a>
                </div>
            </div>
        </body>
        </html>
        """
        try:
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            
            import webbrowser
            webbrowser.open(f"file:///{html_path.replace(chr(92), '/')}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open graphs in browser: {e}")

    def _append_output(self, text):
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)

    def _reset_run_button(self):
        self.run_button.config(state=tk.NORMAL, text="Run Analysis")

if __name__ == "__main__":
    root = tk.Tk()
    app = ArxmlSecDiffGUI(root)
    root.mainloop()
