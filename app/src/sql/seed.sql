-- Seed Fixture F1
TRUNCATE TABLE sessions, articles, users RESTART IDENTITY CASCADE;

-- Insert 3 valid users (admin, alice, bob)
INSERT INTO users (username, password, role) VALUES
('admin', 'admin_pass_2024!', 'administrator'),
('alice', 'alice_pass_secret', 'editor'),
('bob', 'bob_pass_simple', 'viewer');

-- Insert 3 sample articles
INSERT INTO articles (title, content) VALUES
('Báo cáo An toàn Thông tin 2023', 'Nội dung phân tích tổng quan các lỗ hổng OWASP Top 10.'),
('Hướng dẫn Cấu hình ModSecurity', 'Các bước thiết lập CRS v4.0.0 trên nền tảng Nginx.'),
('Kiến trúc Telemetry Đa tầng', 'Mô hình chuẩn hóa log ECS-lite cho hệ thống đo kiểm WAF.');
