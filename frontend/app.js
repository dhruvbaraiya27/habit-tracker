// ==================== Configuration ====================
const API_URL = 'https://habit-tracker-backend-zbsx.onrender.com/api';
let currentToken = null;
let currentUsername = null;

// ==================== Utility Functions ====================
function getToken() {
    return localStorage.getItem('token');
}

function setToken(token) {
    localStorage.setItem('token', token);
    currentToken = token;
}

function getUsername() {
    return localStorage.getItem('username');
}

function setUsername(username) {
    localStorage.setItem('username', username);
    currentUsername = username;
}

function clearAuth() {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    currentToken = null;
    currentUsername = null;
}

function showError(elementId, message) {
    const errorElement = document.getElementById(elementId);
    errorElement.textContent = message;
    errorElement.classList.add('show');
    setTimeout(() => {
        errorElement.classList.remove('show');
    }, 5000);
}

// ==================== Authentication Functions ====================
async function register(username, password) {
    try {
        const response = await fetch(`${API_URL}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Registration failed');
        }

        // Auto-login after registration
        await login(username, password);
    } catch (error) {
        showError('register-error', error.message);
    }
}

async function login(username, password) {
    try {
        const response = await fetch(`${API_URL}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
        });

        if (!response.ok) {
            throw new Error('Invalid credentials');
        }

        const data = await response.json();
        setToken(data.token);
        setUsername(data.username);
        
        showApp();
        loadHabits();
    } catch (error) {
        showError('login-error', error.message);
    }
}

function logout() {
    clearAuth();
    showAuth();
}

// ==================== Habit CRUD Functions ====================
async function loadHabits() {
    const container = document.getElementById('habits-container');
    const emptyState = document.getElementById('empty-state');
    const loadingState = document.getElementById('loading-state');

    loadingState.style.display = 'block';
    container.innerHTML = '';
    emptyState.style.display = 'none';

    try {
        const response = await fetch(`${API_URL}/habits`, {
            headers: {
                'Authorization': `Bearer ${getToken()}`,
            },
        });

        if (!response.ok) {
            throw new Error('Failed to load habits');
        }

        const habits = await response.json();
        loadingState.style.display = 'none';

        if (habits.length === 0) {
            emptyState.style.display = 'block';
        } else {
            habits.forEach(habit => {
                container.appendChild(createHabitCard(habit));
            });
        }
    } catch (error) {
        loadingState.style.display = 'none';
        alert('Failed to load habits: ' + error.message);
    }
}

async function createHabit(name, description) {
    try {
        const response = await fetch(`${API_URL}/habits`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${getToken()}`,
            },
            body: JSON.stringify({ name, description }),
        });

        if (!response.ok) {
            throw new Error('Failed to create habit');
        }

        loadHabits();
    } catch (error) {
        alert('Failed to create habit: ' + error.message);
    }
}

async function updateHabit(id, name, description, streak) {
    try {
        const response = await fetch(`${API_URL}/habits/${id}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${getToken()}`,
            },
            body: JSON.stringify({ name, description, streak }),
        });

        if (!response.ok) {
            throw new Error('Failed to update habit');
        }

        loadHabits();
    } catch (error) {
        alert('Failed to update habit: ' + error.message);
    }
}

async function deleteHabit(id) {
    if (!confirm('Are you sure you want to delete this habit?')) {
        return;
    }

    try {
        const response = await fetch(`${API_URL}/habits/${id}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${getToken()}`,
            },
        });

        if (!response.ok) {
            throw new Error('Failed to delete habit');
        }

        loadHabits();
    } catch (error) {
        alert('Failed to delete habit: ' + error.message);
    }
}

async function incrementStreak(id, currentStreak) {
    try {
        const habit = await getHabit(id);
        await updateHabit(id, habit.name, habit.description, currentStreak + 1);
    } catch (error) {
        alert('Failed to increment streak: ' + error.message);
    }
}

async function getHabit(id) {
    const response = await fetch(`${API_URL}/habits/${id}`, {
        headers: {
            'Authorization': `Bearer ${getToken()}`,
        },
    });

    if (!response.ok) {
        throw new Error('Failed to get habit');
    }

    return await response.json();
}

// ==================== UI Functions ====================
function createHabitCard(habit) {
    const card = document.createElement('div');
    card.className = 'habit-card';
    
    const createdDate = new Date(habit.created_at).toLocaleDateString();
    
    card.innerHTML = `
        <div class="habit-header">
            <h3 class="habit-name">${escapeHtml(habit.name)}</h3>
            <div class="habit-actions">
                <button class="icon-btn" onclick="openEditModal(${habit.id})" title="Edit">✏️</button>
                <button class="icon-btn" onclick="deleteHabit(${habit.id})" title="Delete">🗑️</button>
            </div>
        </div>
        ${habit.description ? `<p class="habit-description">${escapeHtml(habit.description)}</p>` : ''}
        <div class="habit-streak">
            <div class="streak-info">
                <div class="streak-number">${habit.streak}</div>
                <div class="streak-label">day${habit.streak !== 1 ? 's' : ''} streak</div>
            </div>
            <button class="increment-btn" onclick="incrementStreak(${habit.id}, ${habit.streak})">
                +1 Day 🔥
            </button>
        </div>
        <div class="habit-meta">
            <span>Created: ${createdDate}</span>
            <span>ID: ${habit.id}</span>
        </div>
    `;
    
    return card;
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

function showAuth() {
    document.getElementById('auth-section').style.display = 'flex';
    document.getElementById('app-section').style.display = 'none';
}

function showApp() {
    document.getElementById('auth-section').style.display = 'none';
    document.getElementById('app-section').style.display = 'block';
    document.getElementById('username-display').textContent = `👋 ${getUsername()}`;
}

function showLogin() {
    document.getElementById('login-form').style.display = 'block';
    document.getElementById('register-form').style.display = 'none';
    document.querySelectorAll('.tab-btn')[0].classList.add('active');
    document.querySelectorAll('.tab-btn')[1].classList.remove('active');
}

function showRegister() {
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('register-form').style.display = 'block';
    document.querySelectorAll('.tab-btn')[0].classList.remove('active');
    document.querySelectorAll('.tab-btn')[1].classList.add('active');
}

async function openEditModal(id) {
    try {
        const habit = await getHabit(id);
        
        document.getElementById('edit-habit-id').value = habit.id;
        document.getElementById('edit-habit-name').value = habit.name;
        document.getElementById('edit-habit-description').value = habit.description || '';
        document.getElementById('edit-habit-streak').value = habit.streak;
        
        document.getElementById('edit-modal').classList.add('active');
    } catch (error) {
        alert('Failed to load habit: ' + error.message);
    }
}

function closeEditModal() {
    document.getElementById('edit-modal').classList.remove('active');
}

// ==================== Event Listeners ====================
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    await login(username, password);
});

document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('register-username').value;
    const password = document.getElementById('register-password').value;
    await register(username, password);
});

document.getElementById('add-habit-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('habit-name').value;
    const description = document.getElementById('habit-description').value;
    
    await createHabit(name, description);
    
    document.getElementById('habit-name').value = '';
    document.getElementById('habit-description').value = '';
});

document.getElementById('edit-habit-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = document.getElementById('edit-habit-id').value;
    const name = document.getElementById('edit-habit-name').value;
    const description = document.getElementById('edit-habit-description').value;
    const streak = parseInt(document.getElementById('edit-habit-streak').value);
    
    await updateHabit(id, name, description, streak);
    closeEditModal();
});

// Close modal when clicking outside
document.getElementById('edit-modal').addEventListener('click', (e) => {
    if (e.target.id === 'edit-modal') {
        closeEditModal();
    }
});

// ==================== Initialize App ====================
window.onload = () => {
    const token = getToken();
    if (token) {
        showApp();
        loadHabits();
    } else {
        showAuth();
    }
};