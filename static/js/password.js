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

// Advanced password strength checker
function calculatePasswordStrength(password) {
  let score = 0;
  const feedback = [];

  // Length scoring (up to 30 points)
  if (password.length < 8) {
    feedback.push("Password is too short");
  } else {
    score += Math.min(30, password.length * 2);
  }

  // Character variety scoring (up to 20 points)
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSymbol = /[^A-Za-z0-9]/.test(password);
  const varietyCount = [hasUpper, hasLower, hasNumber, hasSymbol].filter(Boolean).length;
  score += varietyCount * 5;

  // Complexity scoring (up to 25 points)
  const uniqueChars = new Set(password).size;
  score += Math.min(25, uniqueChars * 2);

  // Pattern detection (penalties)
  const commonPatterns = [
    /(.)\1{2,}/, // Repeated characters
    /(123|234|345|456|567|678|789|890)/, // Sequential numbers
    /(qwer|asdf|zxcv)/, // Keyboard patterns
    /(password|admin|123456)/i // Common passwords
  ];

  commonPatterns.forEach(pattern => {
    if (pattern.test(password)) {
      score -= 10;
      feedback.push("Contains common patterns");
    }
  });

  // Entropy calculation (up to 25 points)
  const charSet = new Set(password);
  const entropy = Math.log2(Math.pow(charSet.size, password.length));
  score += Math.min(25, entropy / 2);

  // Determine strength level
  let strength;
  if (score < 30) {
    strength = "Very Weak";
  } else if (score < 50) {
    strength = "Weak";
  } else if (score < 70) {
    strength = "Medium";
  } else if (score < 90) {
    strength = "Strong";
  } else {
    strength = "Very Strong";
  }

  return {
    score: Math.min(100, Math.max(0, score)),
    strength,
    feedback
  };
}

function generateStrongPassword() {
  const l = 'abcdefghijklmnopqrstuvwxyz', u = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const n = '0123456789', s = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  let pwd = l[1] + u[1] + n[1] + s[1];
  const all = l + u + n + s;
  for (let i = 0; i < 12; i++) pwd += all[Math.floor(Math.random() * all.length)];
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
  
  // Update basic criteria indicators
  criteriaList.length.className = pwd.length >= 8 ? 'valid' : 'invalid';
  criteriaList.uppercase.className = /[A-Z]/.test(pwd) ? 'valid' : 'invalid';
  criteriaList.lowercase.className = /[a-z]/.test(pwd) ? 'valid' : 'invalid';
  criteriaList.number.className = /\d/.test(pwd) ? 'valid' : 'invalid';
  criteriaList.symbol.className = /[^A-Za-z0-9]/.test(pwd) ? 'valid' : 'invalid';

  // Calculate advanced strength
  const result = calculatePasswordStrength(pwd);
  
  // Update strength display
  strengthText.textContent = result.strength;
  strengthBar.style.width = result.score + '%';
  
  // Set color based on strength
  const colors = {
    'Very Weak': '#f44336',
    'Weak': '#ff9800',
    'Medium': '#ffeb3b',
    'Strong': '#4caf50',
    'Very Strong': '#2196f3'
  };
  strengthBar.style.background = colors[result.strength];
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
    togglePasswordIcon.textContent = type === 'password' ? '��️' : '🙉';
  });
}
