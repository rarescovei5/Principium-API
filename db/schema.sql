CREATE SCHEMA IF NOT EXISTS snippets_extension;
CREATE SCHEMA IF NOT EXISTS write_right;
CREATE SCHEMA IF NOT EXISTS sync_flow;

-- Enable pgcrypto for UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ________________________________ Public ________________________________

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    first_name TEXT,
    last_name TEXT,
    profile_picture_url TEXT,
    password_hash TEXT NOT NULL,
    refresh_token TEXT,
    email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_users_updated_at
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TYPE subscription_plan AS ENUM ('free', 'pro', 'hacker');
CREATE TYPE subscription_status AS ENUM ('active', 'canceled', 'incomplete', 'past_due', 'unpaid');

CREATE TABLE subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  plan subscription_plan NOT NULL DEFAULT 'free',
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  starts_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ends_at TIMESTAMPTZ,
  status subscription_status DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- ________________________________ VSC Snippet Extension ________________________________
CREATE TABLE snippets_extension.snippets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID NOT NULL REFERENCES users(id),
  title TEXT NOT NULL,
  description TEXT,
  code TEXT NOT NULL,
  language TEXT NOT NULL,
  is_public BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  code_tsv tsvector GENERATED ALWAYS AS (to_tsvector('english', code)) STORED
);

CREATE TRIGGER trg_snippets_updated_at
  BEFORE UPDATE ON snippets_extension.snippets
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_snippets_owner ON snippets_extension.snippets(owner_id);
CREATE INDEX idx_snippets_fulltext ON snippets_extension.snippets USING GIN(code_tsv);

CREATE TABLE snippets_extension.tags (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT UNIQUE NOT NULL
);

CREATE TABLE snippets_extension.snippet_tags (
  snippet_id UUID NOT NULL REFERENCES snippets_extension.snippets(id) ON DELETE CASCADE,
  tag_id UUID NOT NULL REFERENCES snippets_extension.tags(id) ON DELETE CASCADE,
  PRIMARY KEY (snippet_id, tag_id)
);

CREATE TABLE snippets_extension.snippet_stars (
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  snippet_id UUID NOT NULL REFERENCES snippets_extension.snippets(id) ON DELETE CASCADE,
  starred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, snippet_id)
);

CREATE INDEX idx_snippet_stars_user ON snippets_extension.snippet_stars(user_id);
CREATE INDEX idx_snippet_stars_snippet ON snippets_extension.snippet_stars(snippet_id);


-- ________________________________ Write Right (Markdown WYSIWYG) ________________________________
CREATE TABLE write_right.folders (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID NOT NULL REFERENCES users(id),
  parent_folder_id UUID REFERENCES write_right.folders(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_folders_updated_at
  BEFORE UPDATE ON write_right.folders
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_folders_owner ON write_right.folders(owner_id);

CREATE TABLE write_right.documents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID NOT NULL REFERENCES users(id),
  folder_id UUID NOT NULL REFERENCES write_right.folders(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  content_tsv tsvector GENERATED ALWAYS AS (to_tsvector('english', content)) STORED
);

CREATE TRIGGER trg_documents_updated_at
  BEFORE UPDATE ON write_right.documents
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_documents_owner ON write_right.documents(owner_id);
CREATE INDEX idx_documents_fulltext ON write_right.documents USING GIN(content_tsv);

-- Workspace sharing table, grants 'view' or 'edit' permission to a user on the whole workspace folder
CREATE TABLE write_right.workspace_shares (
  workspace_folder_id UUID NOT NULL REFERENCES write_right.folders(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  permission TEXT NOT NULL CHECK (permission IN ('view', 'edit')),
  granted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (workspace_folder_id, user_id)
);

CREATE OR REPLACE FUNCTION write_right.enforce_workspace_share_root_folder()
RETURNS TRIGGER AS $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM write_right.folders
    WHERE id = NEW.workspace_folder_id AND parent_folder_id IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'Workspace shares can only be granted on root folders (parent_folder_id IS NULL).';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_enforce_workspace_share_root_folder
BEFORE INSERT OR UPDATE ON write_right.workspace_shares
FOR EACH ROW EXECUTE FUNCTION write_right.enforce_workspace_share_root_folder();


-- ________________________________ Sync Flow (Notion/Trello) ________________________________
CREATE TABLE sync_flow.workspaces (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  description TEXT,
  cover_image_url TEXT,
  owner_id UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_workspaces_updated_at
  BEFORE UPDATE ON sync_flow.workspaces
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_workspaces_owner ON sync_flow.workspaces(owner_id);

CREATE TABLE sync_flow.workspace_members (
  workspace_id UUID NOT NULL REFERENCES sync_flow.workspaces(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('viewer','editor','admin')),
  invited_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE sync_flow.boards (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES sync_flow.workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  icon_name TEXT,
  created_by UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_boards_updated_at
  BEFORE UPDATE ON sync_flow.boards
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_boards_workspace ON sync_flow.boards(workspace_id);

CREATE TABLE sync_flow.tasks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  board_id UUID NOT NULL REFERENCES sync_flow.boards(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT,
  due_date DATE,
  is_done BOOLEAN NOT NULL DEFAULT FALSE,
  assigned_to UUID REFERENCES users(id),
  created_by UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_tasks_updated_at
  BEFORE UPDATE ON sync_flow.tasks
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_tasks_board ON sync_flow.tasks(board_id);
CREATE INDEX idx_tasks_assigned_to ON sync_flow.tasks(assigned_to);

CREATE TABLE sync_flow.labels (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES sync_flow.workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  color TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX ux_labels_workspace_name ON sync_flow.labels(workspace_id, name);

CREATE TABLE sync_flow.task_labels (
  task_id UUID NOT NULL REFERENCES sync_flow.tasks(id) ON DELETE CASCADE,
  label_id UUID NOT NULL REFERENCES sync_flow.labels(id) ON DELETE CASCADE,
  PRIMARY KEY (task_id, label_id)
);

CREATE TABLE sync_flow.attachments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  task_id UUID NOT NULL REFERENCES sync_flow.tasks(id) ON DELETE CASCADE,
  file_url TEXT NOT NULL,
  uploaded_by UUID NOT NULL REFERENCES users(id),
  uploaded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
