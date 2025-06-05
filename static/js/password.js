// ===== Select DOM elements =====
const passwordField = document.getElementById('password');
const confirmField = document.getElementById('confirm_password');
const strengthText = document.getElementById('strength-text');
const strengthSection = document.getElementById('strength-section');
const strengthBar = document.getElementById('strength-bar');

const criteriaList = {
  length: document.getElementById('length'),
  uppercase: document.getElementById('uppercase'),
  lowercase: document.getElementById('lowercase'),
  number: document.getElementById('number'),
  symbol: document.getElementById('symbol')
};

const matchStatus = document.getElementById('match-status');
const submitBtn = document.getElementById('submit-btn');

// ===== Auto-Generated Password Suggestion =====
const suggestionBox = document.getElementById('suggestion-box');
const suggestedPasswordText = document.getElementById('suggested-password');
const acceptBtn = document.getElementById('accept-password');
const refreshBtn = document.getElementById('refresh-password');

// Generate a strong password
function generateStrongPassword() {
  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const numbers = '0123456789';
  const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  
  // Ensure at least one character from each category
  let pwd = '';
  pwd += lowercase[Math.floor(Math.random() * lowercase.length)];
  pwd += uppercase[Math.floor(Math.random() * uppercase.length)];
  pwd += numbers[Math.floor(Math.random() * numbers.length)];
  pwd += symbols[Math.floor(Math.random() * symbols.length)];
  
  // Fill the rest with random characters
  const allChars = lowercase + uppercase + numbers + symbols;
  for (let i = 0; i < 8; i++) {
    pwd += allChars[Math.floor(Math.random() * allChars.length)];
  }
  
  // Shuffle the password
  return pwd.split('').sort(() => Math.random() - 0.5).join('');
}

// Show suggestion box on focus
passwordField.addEventListener('focus', () => {
  const newPwd = generateStrongPassword();
  suggestedPasswordText.textContent = newPwd;
  suggestionBox.style.display = 'flex';
});

// Refresh suggested password
refreshBtn.addEventListener('click', () => {
  const newPwd = generateStrongPassword();
  suggestedPasswordText.textContent = newPwd;
  // Add a subtle animation
  suggestedPasswordText.style.animation = 'none';
  suggestedPasswordText.offsetHeight; // Trigger reflow
  suggestedPasswordText.style.animation = 'fadeIn 0.3s ease-out';
});

// Accept suggestion
acceptBtn.addEventListener('click', () => {
  const suggested = suggestedPasswordText.textContent;
  passwordField.value = suggested;
  confirmField.value = suggested;
  suggestionBox.style.display = 'none';
  updateStrength(); // auto update meter
  checkMatch(); // auto check match
});

// Hide suggestion if user types manually
passwordField.addEventListener('input', () => {
  if (passwordField.value !== suggestedPasswordText.textContent) {
    suggestionBox.style.display = 'none';
  }
  updateStrength();
  checkMatch();
});

// Update confirm password match
confirmField.addEventListener('input', checkMatch);

// ===== Check Strength Function =====
function updateStrength() {
  const pwd = passwordField.value;
  strengthSection.style.display = pwd.length > 0 ? 'block' : 'none';

  const hasLength = pwd.length >= 8;
  const hasUpper = /[A-Z]/.test(pwd);
  const hasLower = /[a-z]/.test(pwd);
  const hasNumber = /\d/.test(pwd);
  const hasSymbol = /[^A-Za-z0-9]/.test(pwd);

  criteriaList.length.className = hasLength ? 'valid' : 'invalid';
  criteriaList.uppercase.className = hasUpper ? 'valid' : 'invalid';
  criteriaList.lowercase.className = hasLower ? 'valid' : 'invalid';
  criteriaList.number.className = hasNumber ? 'valid' : 'invalid';
  criteriaList.symbol.className = hasSymbol ? 'valid' : 'invalid';

  let score = hasLength + hasUpper + hasLower + hasNumber + hasSymbol;
  let strength = "Very Weak";
  let color = "#f44336";

  if (score === 2) { strength = "Weak"; color = "#ff9800"; }
  if (score === 3) { strength = "Medium"; color = "#ffeb3b"; }
  if (score === 4) { strength = "Strong"; color = "#4caf50"; }
  if (score === 5) { strength = "Very Strong"; color = "#2196f3"; }

  strengthText.textContent = strength;
  strengthBar.style.width = (score * 20) + '%';
  strengthBar.style.background = color;
}

// ===== Check Password Match =====
function checkMatch() {
  const pwd = passwordField.value;
  const confirm = confirmField.value;
  if (!pwd || !confirm) {
    matchStatus.textContent = '';
    submitBtn.disabled = true;
    return;
  }

  if (pwd === confirm) {
    matchStatus.textContent = "✅ Passwords match";
    matchStatus.style.color = "green";
    submitBtn.disabled = false;
  } else {
    matchStatus.textContent = "❌ Passwords do not match";
    matchStatus.style.color = "red";
    submitBtn.disabled = true;
  }
}
