-- Seed Fixture F1
TRUNCATE TABLE sessions, articles, users RESTART IDENTITY CASCADE;

-- Insert 3 valid users (admin, alice, bob)
INSERT INTO users (username, password, role) VALUES
('admin', 'admin_pass_2024!', 'administrator'),
('alice', 'alice_pass_secret', 'editor'),
('bob', 'bob_pass_simple', 'viewer');

-- Insert 3 sample articles
INSERT INTO articles (title, content) VALUES
('Information Security Annual Report 2023', 'Comprehensive analytical overview of OWASP Top 10 vulnerabilities.'),
('ModSecurity Configuration Guide', 'Step-by-step instructions for deploying CRS v4.0.0 on Nginx.'),
('Multi-Tier Telemetry Architecture', 'ECS-lite log normalization design for empirical WAF benchmarking.');
