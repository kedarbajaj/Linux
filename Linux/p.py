import re
import tkinter as tk

def check_password_strength(password):
    criteria = {
        "length": len(password) >= 8,
        "uppercase": bool(re.search(r'[A-Z]', password)),
        "lowercase": bool(re.search(r'[a-z]', password)),
        "digits": bool(re.search(r'\d', password)),
        "special_chars": bool(re.search(r'[@$!%*?&#]', password))
    }

    score = sum(criteria.values())
    
    strength_levels = {
        0: "Very Weak",
        1: "Weak",
        2: "Medium",
        3: "Strong",
        4: "Very Strong",
        5: "Excellent"
    }
    
    strength = strength_levels[score]
    
    feedback = {
        "length": "Password should be at least 8 characters long.",
        "uppercase": "Password should contain at least one uppercase letter.",
        "lowercase": "Password should contain at least one lowercase letter.",
        "digits": "Password should contain at least one number.",
        "special_chars": "Password should contain at least one special character (@, $, !, %, *, ?, &, #)."
    }
    
    unmet_criteria = [feedback[key] for key, met in criteria.items() if not met]
    
    return strength, unmet_criteria

def evaluate_password():
    password = password_entry.get()
    strength, feedback = check_password_strength(password)
    
    color_mapping = {
        "Very Weak": "red",
        "Weak": "red",
        "Medium": "orange",
        "Strong": "blue",
        "Very Strong": "green",
        "Excellent": "green"
    }
    
    result_label.config(text=f"Password Strength: {strength}", fg=color_mapping[strength])
    feedback_text.delete("1.0", tk.END)
    
    if feedback:
        feedback_text.insert(tk.END, "To improve your password strength, consider the following:\n")
        for tip in feedback:
            feedback_text.insert(tk.END, f"- {tip}\n")
    else:
        feedback_text.insert(tk.END, "Your password is strong enough.")

# GUI setup
root = tk.Tk()
root.title("Password Complexity Checker")

# Set the background color of the root window
root.configure(bg="green")

frame = tk.Frame(root, padx=20, pady=20, bg="green")
frame.pack(padx=10, pady=10)

password_label = tk.Label(frame, text="Enter your password:", bg="green")
password_label.grid(row=0, column=0, sticky="e")

password_entry = tk.Entry(frame, show="*", width=30)
password_entry.grid(row=0, column=1, padx=10)

evaluate_button = tk.Button(frame, text="Check Strength", command=evaluate_password, bg="white", fg="black")
evaluate_button.grid(row=1, columnspan=2, pady=10)

result_label = tk.Label(frame, text="Password Strength: ", bg="green")
result_label.grid(row=2, columnspan=2)

feedback_text = tk.Text(frame, width=50, height=10, wrap="word", state="normal")
feedback_text.grid(row=3, columnspan=2, pady=10)

root.mainloop()