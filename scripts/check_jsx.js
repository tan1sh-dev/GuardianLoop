const fs = require('fs');
const acorn = require('acorn');
const jsx = require('acorn-jsx');
const parser = acorn.Parser.extend(jsx());

const files = ['data.jsx', 'quizData.jsx', 'ui-kit.jsx', 'live-scan.jsx', 'screens.jsx', 'learning.jsx', 'app.jsx', 'bootstrap.jsx'];

for (let f of files) {
    const code = fs.readFileSync('src/guardianloop/ui/dashboard/' + f, 'utf8');
    try {
        // We use ecmaVersion: 'latest' so it handles async/await, optional chaining, etc.
        parser.parse(code, { sourceType: 'module', ecmaVersion: 'latest' });
        console.log(f + ' OK');
    } catch(e) {
        console.log(f + ' ERROR: ' + e.message);
    }
}
