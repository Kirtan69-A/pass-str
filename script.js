// ========== DOM Elements ==========
var passwordInput = document.getElementById('passwordInput');
var toggleBtn = document.getElementById('toggleBtn');
var copyBtn = document.getElementById('copyBtn');
var copyFeedback = document.getElementById('copyFeedback');
var generateBtn = document.getElementById('generateBtn');
var scoreDisplay = document.getElementById('scoreDisplay');
var strengthBar = document.getElementById('strengthBar');
var strengthLabel = document.getElementById('strengthLabel');
var entropyValue = document.getElementById('entropyValue');
var timeToCrackEl = document.getElementById('timeToCrack');
var themeToggle = document.getElementById('themeToggle');
var checkLength = document.getElementById('checkLength');
var checkUpper = document.getElementById('checkUpper');
var checkLower = document.getElementById('checkLower');
var checkNumber = document.getElementById('checkNumber');
var checkSpecial = document.getElementById('checkSpecial');
var checkPatterns = document.getElementById('checkPatterns');

// ========== Common / Weak Passwords (lowercase for comparison) ==========
const COMMON_PASSWORDS = [
  '123456', 'password', '12345678', 'qwerty', '123456789', '12345',
  '1234', '111111', '1234567', 'dragon', '123123', 'baseball',
  'abc123', 'football', 'monkey', 'letmein', '696969', 'shadow',
  'master', '666666', 'qwertyuiop', '123321', 'mustang', '1234567890',
  'michael', '654321', 'pussy', 'superman', '1qaz2wsx', '7777777',
  'fuckyou', '121212', '000000', 'qazwsx', '123qwe', 'killer',
  'trustno1', 'jordan', 'jennifer', 'zxcvbnm', 'asdfgh', 'hunter',
  'buster', 'soccer', 'harley', 'batman', 'andrew', 'tigger',
  'sunshine', 'iloveyou', 'fuckme', '2000', 'charlie', 'robert',
  'thomas', 'hockey', 'ranger', 'daniel', 'starwars', 'klaster',
  '112233', 'george', 'asshole', 'computer', 'michelle', 'jessica',
  'pepper', '1111', 'zxcvbn', '555555', '11111111', '131313',
  'freedom', '777777', 'pass', 'fuck', 'maggie', '159753',
  'aaaaaa', 'ginger', 'princess', 'joshua', 'cheese', 'amanda',
  'summer', 'love', 'ashley', 'nicole', 'chelsea', 'biteme',
  'matthew', 'access', 'yankees', '987654321', 'dallas', 'austin',
  'thunder', 'taylor', 'matrix'
];

// Simple patterns (single-type or all-same) – for full-password check only
const SIMPLE_PATTERNS = [
  /^[0-9]+$/,
  /^[a-z]+$/,
  /^[A-Z]+$/
];

// Keyboard and sequence patterns – detected anywhere in password (lowercase)
const KEYBOARD_PATTERNS = ['qwerty', 'qwertyuiop', 'asdf', 'asdfgh', 'zxcv', 'zxcvbn', '1qaz2wsx', 'qazwsx', '123qwe', 'qweasd', 'pyfgcrl'];
const ALPHA_FWD = 'abcdefghijklmnopqrstuvwxyz';
const ALPHA_REV = 'zyxwvutsrqponmlkjihgfedcba';
const NUM_FWD = '0123456789';
const NUM_REV = '9876543210';
const MAX_COMMON_SUFFIX = 4;  // allow common + up to 4 digits/simple suffix

/** Returns true if password exactly matches or is common + small variation (e.g. password1, password123). */
function isCommonPasswordWeak(password) {
  if (!password) return false;
  const lower = password.toLowerCase();
  for (let i = 0; i < COMMON_PASSWORDS.length; i++) {
    const c = COMMON_PASSWORDS[i];
    if (lower === c) return true;
    if (lower.length > c.length && lower.indexOf(c) === 0) {
      const suffix = lower.slice(c.length);
      if (suffix.length <= MAX_COMMON_SUFFIX && /^[\d!@#$%*]*$/.test(suffix)) return true;
    }
  }
  return false;
}

/** Returns true if password has 5+ same character in a row */
function hasLongRepeatedRun(password) {
  if (!password || password.length < 5) return false;
  let run = 1;
  for (let i = 1; i < password.length; i++) {
    if (password[i] === password[i - 1]) {
      run++;
      if (run >= 5) return true;
    } else {
      run = 1;
    }
  }
  return false;
}

/** Returns max run length of same character (0 if none 3+). */
function getMaxRepeatedRun(password) {
  if (!password || password.length < 3) return 0;
  let run = 1, maxRun = 0;
  for (let i = 1; i < password.length; i++) {
    if (password[i] === password[i - 1]) {
      run++;
    } else {
      if (run > maxRun) maxRun = run;
      run = 1;
    }
  }
  if (run > maxRun) maxRun = run;
  return maxRun;
}

/** Returns true if password is all the same character */
function isAllSameCharacter(password) {
  if (!password || password.length < 2) return false;
  const first = password[0];
  for (let i = 1; i < password.length; i++) {
    if (password[i] !== first) return false;
  }
  return true;
}

/** Returns true if password has 3+ same character in a row anywhere */
function hasRepeatedRun(password) {
  return getMaxRepeatedRun(password) >= 3;
}

/** Returns true if substring is a 3+ forward or reverse sequence in alphabet/digits */
function isSequence(s, alphabet) {
  if (s.length < 3) return false;
  for (let i = 0; i <= s.length - 3; i++) {
    const sub = s.slice(i, i + 3);
    if (alphabet.indexOf(sub) !== -1) return true;
    const rev = sub.split('').reverse().join('');
    if (alphabet.indexOf(rev) !== -1) return true;
  }
  return false;
}

/** Count of 3+ alphabetical sequences (forward or reverse) anywhere */
function countAlphaSequences(password) {
  if (!password || password.length < 3) return 0;
  const lower = password.toLowerCase().replace(/[^a-z]/g, '');
  let n = 0;
  for (let i = 0; i <= lower.length - 3; i++) {
    const sub = lower.slice(i, i + 3);
    if (ALPHA_FWD.indexOf(sub) !== -1 || ALPHA_REV.indexOf(sub) !== -1) n++;
  }
  return n;
}

/** Count of 3+ numeric sequences (forward or reverse) anywhere */
function countNumericSequences(password) {
  if (!password || password.length < 3) return 0;
  const digits = password.replace(/[^0-9]/g, '');
  let n = 0;
  for (let i = 0; i <= digits.length - 3; i++) {
    const sub = digits.slice(i, i + 3);
    if (NUM_FWD.indexOf(sub) !== -1 || NUM_REV.indexOf(sub) !== -1) n++;
  }
  return n;
}

/** Returns true if password contains a known keyboard pattern anywhere */
function hasKeyboardPattern(password) {
  if (!password) return false;
  const lower = password.toLowerCase();
  for (let i = 0; i < KEYBOARD_PATTERNS.length; i++) {
    if (lower.indexOf(KEYBOARD_PATTERNS[i]) !== -1) return true;
  }
  return false;
}

// ========== Strength Categories ==========
// Weak (red), Medium (orange), Strong (green), Very Strong (cyan/blue)
function getStrengthCategory(score) {
  if (score <= 25) return { label: 'Very Weak', class: 'weak' };
  if (score <= 50) return { label: 'Weak', class: 'medium' };
  if (score <= 75) return { label: 'Strong', class: 'strong' };
  return { label: 'Very Strong', class: 'very-strong' };
}

// ========== Checklist state (for UI) ==========
function getChecklistState(password) {
  if (!password) {
    return { length: false, upper: false, lower: false, number: false, special: false, noPatterns: false };
  }
  var len = password.length >= 12;
  var upper = /[A-Z]/.test(password);
  var lower = /[a-z]/.test(password);
  var number = /[0-9]/.test(password);
  var special = /[^a-zA-Z0-9]/.test(password);
  var noPatterns = !isCommonPasswordWeak(password) && !hasKeyboardPattern(password) &&
    countNumericSequences(password) === 0 && countAlphaSequences(password) === 0 && !hasRepeatedRun(password);
  return { length: len, upper: upper, lower: lower, number: number, special: special, noPatterns: noPatterns };
}

// ========== Time to crack (approximate) ==========
// Assumes 10 billion guesses per second; time = 2^entropy / 1e10 seconds
function getTimeToCrack(entropyBits) {
  if (entropyBits <= 0) return '—';
  var combinations = Math.pow(2, entropyBits);
  var guessesPerSec = 1e10;
  var seconds = combinations / guessesPerSec;
  if (seconds < 1) return '&lt; 1 second';
  if (seconds < 60) return seconds.toFixed(0) + ' seconds';
  var minutes = seconds / 60;
  if (minutes < 60) return minutes.toFixed(1) + ' minutes';
  var hours = minutes / 60;
  if (hours < 24) return hours.toFixed(1) + ' hours';
  var days = hours / 24;
  if (days < 365) return days.toFixed(0) + ' days';
  var years = days / 365;
  if (years < 1000) return years.toFixed(1) + ' years';
  if (years < 1e6) return (years / 1000).toFixed(1) + ' thousand years';
  if (years < 1e9) return (years / 1e6).toFixed(1) + ' million years';
  return (years / 1e9).toFixed(1) + ' billion years';
}

// ========== Password Strength Algorithm (1–100) ==========
// Designed so a perfect password (long, 4 char types, no patterns) can reach 100.
function calculateScore(password) {
  if (!password || password.length === 0) return 0;

  const len = password.length;

  // --- 1. Length score (max 40) ---
  let lengthScore = 0;
  if (len >= 8) lengthScore += Math.min(len, 12) * 2;   // 2 pts per char up to 12 chars (max 24)
  if (len >= 12) lengthScore += 8;                        // bonus 12+
  if (len >= 16) lengthScore += 4;                        // bonus 16+
  if (len >= 20) lengthScore += 4;                        // bonus 20+ (total length max 40)

  // --- 2. Character variety (max 45) ---
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const hasSpecial = /[^a-zA-Z0-9]/.test(password);
  let varietyScore = 0;
  if (hasLower) varietyScore += 10;
  if (hasUpper) varietyScore += 10;
  if (hasDigit) varietyScore += 10;
  if (hasSpecial) varietyScore += 15;  // special chars weighted higher

  // --- 3. Diversity bonus (max 15) ---
  const types = [hasLower, hasUpper, hasDigit, hasSpecial].filter(Boolean).length;
  let diversityScore = 0;
  if (types >= 3) diversityScore += 8;
  if (types === 4) diversityScore += 7;

  // Raw score: 40 + 45 + 15 = 100 max before penalties
  let score = lengthScore + varietyScore + diversityScore;

  // --- 4. Penalties (proportional where appropriate; strong long passwords less punished) ---
  const isOtherwiseStrong = len >= 12 && types >= 3;

  if (isCommonPasswordWeak(password)) {
    score -= 40;
  }

  var maxRun = getMaxRepeatedRun(password);
  if (maxRun >= 5) {
    score -= isOtherwiseStrong ? 6 : Math.min(25, 3 * maxRun);
  } else if (maxRun >= 3) {
    score -= isOtherwiseStrong ? 3 : Math.min(12, 2 * maxRun);
  }

  if (isAllSameCharacter(password)) {
    score -= 15;
  } else if (SIMPLE_PATTERNS.some(function (p) { return p.test(password); })) {
    score -= 12;
  }

  var numSeq = countNumericSequences(password);
  var alphaSeq = countAlphaSequences(password);
  var seqPenalty = Math.min(15, numSeq * 3 + alphaSeq * 2);
  if (seqPenalty > 0) score -= isOtherwiseStrong ? Math.min(6, seqPenalty) : seqPenalty;

  if (hasKeyboardPattern(password)) {
    score -= isOtherwiseStrong ? 5 : 12;
  }

  return Math.max(1, Math.min(100, Math.round(score)));
}

// ========== Entropy (bits) – base formula minus predictability penalties ==========
function calculateEntropy(password) {
  if (!password || password.length === 0) return 0;
  var poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;
  if (poolSize === 0) return 0;
  var baseEntropy = password.length * Math.log2(poolSize);

  var penalty = 0;
  var maxRun = getMaxRepeatedRun(password);
  if (maxRun >= 3) penalty += Math.min(8, maxRun * 1.5);
  var nSeq = countNumericSequences(password) + countAlphaSequences(password);
  if (nSeq > 0) penalty += Math.min(6, nSeq * 1.5);
  if (hasKeyboardPattern(password)) penalty += 4;
  if (isCommonPasswordWeak(password)) penalty += 10;

  var effective = Math.max(0, baseEntropy - penalty);
  return Math.round(effective * 10) / 10;
}

// ========== Update UI from current password (real-time) ==========
function updateUI() {
  try {
    var password = passwordInput.value;
    var score = calculateScore(password);
    var category = getStrengthCategory(score);
    var entropy = calculateEntropy(password);
    var checklistState = getChecklistState(password);

    // Score and label
    scoreDisplay.textContent = password.length ? score : '—';
    strengthLabel.textContent = password.length ? category.label : '—';
    strengthLabel.className = 'strength-category ' + (password.length ? category.class : '');
    if (password.length) strengthLabel.classList.add('is-visible'); else strengthLabel.classList.remove('is-visible');

    // Animated bar
    strengthBar.style.width = score + '%';
    strengthBar.className = 'strength-bar-fill ' + (password.length ? category.class : '');

    // Entropy
    entropyValue.textContent = password.length ? entropy : '—';

    // Time to crack
    timeToCrackEl.innerHTML = password.length ? getTimeToCrack(entropy) : '—';

    // Checklist: met / unmet (highlight unmet)
    checkLength.classList.toggle('met', checklistState.length); checkLength.classList.toggle('unmet', !checklistState.length);
    checkUpper.classList.toggle('met', checklistState.upper); checkUpper.classList.toggle('unmet', !checklistState.upper);
    checkLower.classList.toggle('met', checklistState.lower); checkLower.classList.toggle('unmet', !checklistState.lower);
    checkNumber.classList.toggle('met', checklistState.number); checkNumber.classList.toggle('unmet', !checklistState.number);
    checkSpecial.classList.toggle('met', checklistState.special); checkSpecial.classList.toggle('unmet', !checklistState.special);
    checkPatterns.classList.toggle('met', checklistState.noPatterns); checkPatterns.classList.toggle('unmet', !checklistState.noPatterns);
  } catch (err) {
    scoreDisplay.textContent = '—';
    strengthLabel.textContent = '—';
    strengthLabel.className = 'strength-category';
    strengthBar.style.width = '0%';
    strengthBar.className = 'strength-bar-fill';
    entropyValue.textContent = '—';
    if (timeToCrackEl) timeToCrackEl.textContent = '—';
  }
}

// ========== Show / Hide password (animated eye icon) ==========
toggleBtn.addEventListener('click', function () {
  var type = passwordInput.getAttribute('type');
  var isPassword = type === 'password';
  passwordInput.setAttribute('type', isPassword ? 'text' : 'password');
  toggleBtn.classList.toggle('is-visible', isPassword);
  toggleBtn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
});

// ========== Copy to clipboard ==========
if (copyBtn) {
  copyBtn.addEventListener('click', function () {
    var val = passwordInput.value;
    if (!val) return;
    navigator.clipboard.writeText(val).then(function () {
      copyBtn.classList.add('copied');
      if (copyFeedback) copyFeedback.textContent = 'Copied!';
      setTimeout(function () {
        copyBtn.classList.remove('copied');
      }, 2000);
    });
  });
}

// ========== Secure randomness (crypto.getRandomValues) ==========
function secureRandomInt(maxExclusive) {
  if (maxExclusive <= 0) return 0;
  var array = new Uint32Array(1);
  window.crypto.getRandomValues(array);
  return array[0] % maxExclusive;
}

function secureShuffle(arr) {
  var a = arr.slice();
  for (var i = a.length - 1; i > 0; i--) {
    var j = secureRandomInt(i + 1);
    var t = a[i];
    a[i] = a[j];
    a[j] = t;
  }
  return a;
}

// ========== Generate strong password (16 chars: upper, lower, numbers, symbols) ==========
generateBtn.addEventListener('click', () => {
  var upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  var lower = 'abcdefghijklmnopqrstuvwxyz';
  var numbers = '0123456789';
  var symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  var all = upper + lower + numbers + symbols;

  var result = '';
  result += upper[secureRandomInt(upper.length)];
  result += lower[secureRandomInt(lower.length)];
  result += numbers[secureRandomInt(numbers.length)];
  result += symbols[secureRandomInt(symbols.length)];

  for (var i = 4; i < 16; i++) {
    result += all[secureRandomInt(all.length)];
  }

  result = secureShuffle(result.split('')).join('');

  passwordInput.value = result;
  passwordInput.setAttribute('type', 'text');
  toggleBtn.classList.add('is-visible');
  toggleBtn.setAttribute('aria-label', 'Hide password');
  updateUI();
});

// ========== Theme (light/dark) toggle ==========
function applyTheme(theme) {
  var root = document.documentElement;
  root.setAttribute('data-theme', theme);
  try { localStorage.setItem('password-checker-theme', theme); } catch (e) {}
}

if (themeToggle) {
  themeToggle.addEventListener('click', function () {
    var root = document.documentElement;
    var current = root.getAttribute('data-theme') || 'dark';
    var next = current === 'dark' ? 'light' : 'dark';
    applyTheme(next);
  });
}

(function initTheme() {
  try {
    var saved = localStorage.getItem('password-checker-theme');
    if (saved === 'light' || saved === 'dark') applyTheme(saved);
  } catch (e) {}
})();

// ========== Real-time updates ==========
passwordInput.addEventListener('input', updateUI);
passwordInput.addEventListener('paste', function () { setTimeout(updateUI, 0); });

// Initial state
updateUI();

// ========== Floating particle background (cyber style) ==========
(function initParticles() {
  var canvas = document.getElementById('particleCanvas');
  if (!canvas) return;

  var ctx = canvas.getContext('2d');
  var particles = [];
  var count = 48;

  function resize() {
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = window.innerWidth * dpr;
    canvas.height = window.innerHeight * dpr;
    canvas.style.width = window.innerWidth + 'px';
    canvas.style.height = window.innerHeight + 'px';
    ctx.scale(dpr, dpr);
    particles = [];
    var w = window.innerWidth;
    var h = window.innerHeight;
    for (var i = 0; i < count; i++) {
      particles.push({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.3,
        r: 1 + Math.random() * 1.5,
        opacity: 0.15 + Math.random() * 0.2
      });
    }
  }

  function draw() {
    var w = window.innerWidth;
    var h = window.innerHeight;
    ctx.clearRect(0, 0, w, h);
    var isLight = document.documentElement.getAttribute('data-theme') === 'light';
    var color = isLight ? 'rgba(9, 105, 218, 0.4)' : 'rgba(0, 212, 255, 0.5)';
    particles.forEach(function (p) {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0 || p.x > w) p.vx *= -1;
      if (p.y < 0 || p.y > h) p.vy *= -1;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.globalAlpha = p.opacity;
      ctx.fill();
      ctx.globalAlpha = 1;
    });
    requestAnimationFrame(draw);
  }

  window.addEventListener('resize', resize);
  resize();
  draw();
})();
