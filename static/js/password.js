const passwordField = document.getElementById('password');
const confirmField = document.getElementById('confirm_password');
const strengthText = document.getElementById('strength-text');
const strengthSection = document.getElementById('strength-section');
const strengthBar = document.getElementById('strength-bar');
const matchStatus = document.getElementById('match-status');
const submitBtn = document.getElementById('submit-btn');

const criteriaList = {
  length: document.getElementById('length'),
  uppercase: document.getElementById('uppercase'),
  lowercase: document.getElementById('lowercase'),
  number: document.getElementById('number'),
  symbol: document.getElementById('symbol')
};

const suggestionBox = document.getElementById('suggestion-box');
const suggestedPasswordText = document.getElementById('suggested-password');
const acceptBtn = document.getElementById('accept-password');
const refreshBtn = document.getElementById('refresh-password');

function generateStrongPassword() {
  const l = 'abcdefghijklmnopqrstuvwxyz', u = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const n = '0123456789', s = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  let pwd = l[1] + u[1] + n[1] + s[1];
  const all = l + u + n + s;
  for (let i = 0; i < 8; i++) pwd += all[Math.floor(Math.random() * all.length)];
  return pwd.split('').sort(() => Math.random() - 0.5).join('');
}

passwordField.addEventListener('focus', () => {
  suggestedPasswordText.textContent = generateStrongPassword();
  suggestionBox.style.display = 'flex';
});

refreshBtn.addEventListener('click', () => {
  suggestedPasswordText.textContent = generateStrongPassword();
});

acceptBtn.addEventListener('click', () => {
  const pwd = suggestedPasswordText.textContent;
  passwordField.value = pwd;
  confirmField.value = pwd;
  passwordField.type = 'password';
  suggestionBox.style.display = 'none';
  updateStrength();
  checkMatch();
});

passwordField.addEventListener('input', () => {
  if (passwordField.value !== suggestedPasswordText.textContent) {
    suggestionBox.style.display = 'none';
  }
  updateStrength();
  checkMatch();
});

confirmField.addEventListener('input', checkMatch);

function updateStrength() {
  const pwd = passwordField.value;
  strengthSection.style.display = pwd ? 'block' : 'none';
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
  const strengths = ['Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong'];
  const colors = ['#f44336', '#ff9800', '#ffeb3b', '#4caf50', '#2196f3'];

  strengthText.textContent = strengths[score - 1] || 'Very Weak';
  strengthBar.style.width = (score * 20) + '%';
  strengthBar.style.background = colors[score - 1] || '#f44336';
}

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

// Toggle password visibility
function togglePassword(fieldId) {
  const field = document.getElementById(fieldId);
  field.type = field.type === 'password' ? 'text' : 'password';
}

// Add event listener for password toggle on login page
const loginPasswordField = document.getElementById('login-password');
const togglePasswordIcon = document.getElementById('toggle-password');

if (loginPasswordField && togglePasswordIcon) {
  togglePasswordIcon.addEventListener('click', () => {
    const type = loginPasswordField.getAttribute('type') === 'password' ? 'text' : 'password';
    loginPasswordField.setAttribute('type', type);
    // Change the icon
    togglePasswordIcon.textContent = type === 'password' ? '��️' : '🙈';
  });
}
