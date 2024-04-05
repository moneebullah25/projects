import tkinter as tk
import tkinter.filedialog as filedialog
import re

class App:
    def __init__(self, master):
        self.master = master
        master.title("Comment Remover")

        # Create widgets
        self.label1 = tk.Label(master, text="Select a Python file to remove comments from:")
        self.button1 = tk.Button(master, text="Browse...", command=self.browse_file)
        self.label2 = tk.Label(master, text="Remove redundant newlines:")
        self.var1 = tk.BooleanVar()
        self.var1.set(False)
        self.radio1 = tk.Radiobutton(master, text="Yes", variable=self.var1, value=True)
        self.radio2 = tk.Radiobutton(master, text="No", variable=self.var1, value=False)
        self.button2 = tk.Button(master, text="Remove Comments", command=self.remove_comments)
        self.status_label = tk.Label(master, text="")

        # Lay out widgets
        self.label1.grid(row=0, column=0, padx=10, pady=10)
        self.button1.grid(row=0, column=1, padx=10, pady=10)
        self.label2.grid(row=1, column=0, padx=10, pady=10)
        self.radio1.grid(row=1, column=1, padx=10, pady=10)
        self.radio2.grid(row=1, column=2, padx=10, pady=10)
        self.button2.grid(row=2, column=0, columnspan=3, padx=10, pady=10)
        self.status_label.grid(row=3, column=0, columnspan=3, padx=10, pady=10)

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Python Files", "*.py")])
        if file_path:
            self.file_path = file_path
            self.status_label.configure(text=f"Selected file: {file_path}")

    def remove_comments(self):
        try:
            # Read the contents of the file
            with open(self.file_path, 'r') as f:
                content = f.read()

            # Remove comments
            content = re.sub(r'#.*$', '', content, flags=re.MULTILINE)
            content = re.sub(r"'''.*?'''.*?", '', content, flags=re.DOTALL)
            content = re.sub(r'""".*?""".*?', '', content, flags=re.DOTALL)

            # Remove redundant newlines if selected
            if self.var1.get():
                content = re.sub(r'\n{2,}', '\n', content)

            # Write the modified contents to a new file
            new_file_path = filedialog.asksaveasfilename(defaultextension=".py", filetypes=[("Python Files", "*.py")])
            if new_file_path:
                with open(new_file_path, 'w') as f:
                    f.write(content)
                self.status_label.configure(text=f"Comments removed from {self.file_path} and saved to {new_file_path}")
            else:
                self.status_label.configure(text="Save operation cancelled")
        except AttributeError:
            self.status_label.configure(text="No file selected")
        except Exception as e:
            self.status_label.configure(text=f"Error: {str(e)}")

# Create and run the application
root = tk.Tk()
app = App(root)
root.mainloop()
