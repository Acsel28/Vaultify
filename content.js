function checkStrength(password) {
  let score = 0;
  if (password.length >= 8) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  return score; // 0 = weak, 4 = strong
}

function suggestPassword() {
  const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
  let password = "";
  for (let i = 0; i < 16; i++) {
    password += charset[Math.floor(Math.random() * charset.length)];
  }
  return password;
}

// Attach listener to password fields
document.addEventListener("input", (e) => {
  if (e.target.type === "password") {
    const strength = checkStrength(e.target.value);
    if (strength < 3) {
      let suggestion = suggestPassword();
      let msg = document.getElementById("pw-helper");
      if (!msg) {
        msg = document.createElement("div");
        msg.id = "pw-helper";
        msg.style.position = "absolute";
        msg.style.background = "#fff3cd";
        msg.style.border = "1px solid #ffc107";
        msg.style.padding = "5px";
        msg.style.marginTop = "5px";
        e.target.insertAdjacentElement("afterend", msg);
      }
      msg.innerText = `⚠️ Weak password. Try: ${suggestion}`;
    }
  }
});
