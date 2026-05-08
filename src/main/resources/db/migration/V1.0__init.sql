-- Roles table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'roles')
CREATE TABLE roles (
    id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWID(),
    name NVARCHAR(50) NOT NULL,
    description NVARCHAR(255),
    CONSTRAINT pk_roles PRIMARY KEY (id),
    CONSTRAINT uq_roles_name UNIQUE (name)
);

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'users')
CREATE TABLE users (
    id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWID(),
    email NVARCHAR(255) NOT NULL,
    username NVARCHAR(100) NOT NULL,
    password NVARCHAR(255) NOT NULL,
    first_name NVARCHAR(100),
    last_name NVARCHAR(100),
    phone NVARCHAR(20),
    date_of_birth DATE,
    status NVARCHAR(20) NOT NULL DEFAULT 'PENDING',
    email_verified BIT NOT NULL DEFAULT 0,
    phone_verified BIT NOT NULL DEFAULT 0,
    two_factor_enabled BIT NOT NULL DEFAULT 0,
    two_factor_secret NVARCHAR(255),
    failed_login_attempts INT NOT NULL DEFAULT 0,
    locked_until DATETIMEOFFSET,
    last_login_at DATETIMEOFFSET,
    last_login_ip NVARCHAR(45),
    created_at DATETIMEOFFSET NOT NULL DEFAULT SYSUTCDATETIME(),
    updated_at DATETIMEOFFSET NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT pk_users PRIMARY KEY (id),
    CONSTRAINT uq_users_email UNIQUE (email),
    CONSTRAINT uq_users_username UNIQUE (username)
);

-- User-Roles join table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'user_roles')
CREATE TABLE user_roles (
    user_id UNIQUEIDENTIFIER NOT NULL,
    role_id UNIQUEIDENTIFIER NOT NULL,
    CONSTRAINT pk_user_roles PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles(id)
);

MERGE INTO roles AS target
USING (VALUES
    ('ROLE_USER', 'Standard user'),
    ('ROLE_ADMIN', 'Administrator')
) AS source (name, description)
ON target.name = source.name
WHEN NOT MATCHED THEN
    INSERT (id, name, description)
    VALUES (NEWID(), source.name, source.description);

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_users_email')
    CREATE INDEX idx_users_email ON users(email);
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_users_username')
    CREATE INDEX idx_users_username ON users(username);
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_users_status')
    CREATE INDEX idx_users_status ON users(status);
