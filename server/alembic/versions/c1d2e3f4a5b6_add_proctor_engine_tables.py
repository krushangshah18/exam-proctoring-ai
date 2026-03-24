"""add proctor engine tables and columns

Revision ID: c1d2e3f4a5b6
Revises: b2c3d4e5f6a7
Create Date: 2026-03-23 00:00:00.000000

Adds:
  - engine_containers       (new table — seeded from PROCTOR_ENGINE_URLS)
  - exam_engine_assignments (new table — exam ↔ container junction)
  - engine_settings         (new table — system admin global config, single row)
  - exams.detection_config  (JSON — exam admin per-exam detection toggles)
  - exam_sessions.proctor_pc_id      (engine's device_id for this session)
  - exam_sessions.proctor_engine_url (which container this student is on)
  - exam_sessions.proctor_report_id  (engine report folder name, set on close)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


revision: str = 'c1d2e3f4a5b6'
down_revision: Union[str, Sequence[str], None] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── engine_containers ────────────────────────────────────────────────────
    op.create_table(
        'engine_containers',
        sa.Column('id',           UUID(as_uuid=True), primary_key=True),
        sa.Column('created_at',   sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at',   sa.DateTime(), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
        sa.Column('url',          sa.String(),   nullable=False),
        sa.Column('max_sessions', sa.Integer(),  nullable=False, server_default='3'),
        sa.Column('is_active',    sa.Boolean(),  nullable=False, server_default='true'),
        sa.UniqueConstraint('url', name='uq_engine_containers_url'),
    )

    # ── exam_engine_assignments ──────────────────────────────────────────────
    op.create_table(
        'exam_engine_assignments',
        sa.Column('id',           UUID(as_uuid=True), primary_key=True),
        sa.Column('created_at',   sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at',   sa.DateTime(), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
        sa.Column('exam_id',      UUID(as_uuid=True), sa.ForeignKey('exams.id'), nullable=False),
        sa.Column('container_id', UUID(as_uuid=True), sa.ForeignKey('engine_containers.id'), nullable=False),
    )
    op.create_index('idx_engine_assign_exam',      'exam_engine_assignments', ['exam_id'])
    op.create_index('idx_engine_assign_container', 'exam_engine_assignments', ['container_id'])

    # ── engine_settings (single row) ─────────────────────────────────────────
    op.create_table(
        'engine_settings',
        sa.Column('id',                       UUID(as_uuid=True), primary_key=True),
        sa.Column('created_at',               sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at',               sa.DateTime(), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
        # Head pose thresholds
        sa.Column('look_away_yaw',            sa.Float(), nullable=False, server_default='0.20'),
        sa.Column('look_down_pitch',          sa.Float(), nullable=False, server_default='0.13'),
        sa.Column('look_up_pitch',            sa.Float(), nullable=False, server_default='-0.10'),
        sa.Column('gaze_left',                sa.Float(), nullable=False, server_default='-0.13'),
        sa.Column('gaze_right',               sa.Float(), nullable=False, server_default='0.13'),
        # Duration gates
        sa.Column('looking_away_threshold',   sa.Float(), nullable=False, server_default='2.0'),
        sa.Column('gaze_threshold',           sa.Float(), nullable=False, server_default='1.5'),
        sa.Column('fake_window',              sa.Float(), nullable=False, server_default='15.0'),
        # Risk scores
        sa.Column('gaze_score',               sa.Float(), nullable=False, server_default='5.0'),
        sa.Column('phone_score_2nd',          sa.Float(), nullable=False, server_default='25.0'),
        sa.Column('phone_score_3rd',          sa.Float(), nullable=False, server_default='50.0'),
        sa.Column('book_score',               sa.Float(), nullable=False, server_default='20.0'),
        sa.Column('headphone_score',          sa.Float(), nullable=False, server_default='20.0'),
        sa.Column('earbud_score',             sa.Float(), nullable=False, server_default='20.0'),
        sa.Column('tab_switch_score',         sa.Float(), nullable=False, server_default='15.0'),
        sa.Column('multi_people_score_2nd',   sa.Float(), nullable=False, server_default='20.0'),
        sa.Column('multi_people_score_3rd',   sa.Float(), nullable=False, server_default='50.0'),
        sa.Column('no_person_score_1',        sa.Float(), nullable=False, server_default='25.0'),
        sa.Column('no_person_score_2',        sa.Float(), nullable=False, server_default='50.0'),
        sa.Column('fake_presence_score_1',    sa.Float(), nullable=False, server_default='30.0'),
        sa.Column('fake_presence_score_2',    sa.Float(), nullable=False, server_default='60.0'),
        # State thresholds
        sa.Column('state_warning',            sa.Float(), nullable=False, server_default='30.0'),
        sa.Column('state_high_risk',          sa.Float(), nullable=False, server_default='60.0'),
        sa.Column('state_admin_review',       sa.Float(), nullable=False, server_default='100.0'),
        # Decay
        sa.Column('decay_amount',             sa.Float(), nullable=False, server_default='5.0'),
        # Termination rules
        sa.Column('tab_switch_terminate_count', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('multi_people_terminate_s', sa.Float(), nullable=False, server_default='20.0'),
        sa.Column('no_person_terminate_s',    sa.Float(), nullable=False, server_default='20.0'),
        # YOLO confidence
        sa.Column('yolo_phone_conf',          sa.Float(), nullable=False, server_default='0.65'),
        sa.Column('yolo_book_conf',           sa.Float(), nullable=False, server_default='0.70'),
        sa.Column('yolo_audio_conf',          sa.Float(), nullable=False, server_default='0.41'),
        sa.Column('yolo_person_conf',         sa.Float(), nullable=False, server_default='0.30'),
    )

    # ── exams columns ─────────────────────────────────────────────────────────
    op.add_column('exams', sa.Column('detection_config', sa.JSON(), nullable=True))

    # ── exam_sessions columns ─────────────────────────────────────────────────
    op.add_column('exam_sessions', sa.Column('proctor_pc_id',      sa.String(), nullable=True))
    op.add_column('exam_sessions', sa.Column('proctor_engine_url', sa.String(), nullable=True))
    op.add_column('exam_sessions', sa.Column('proctor_report_id',  sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column('exam_sessions', 'proctor_report_id')
    op.drop_column('exam_sessions', 'proctor_engine_url')
    op.drop_column('exam_sessions', 'proctor_pc_id')
    op.drop_column('exams', 'detection_config')
    op.drop_table('engine_settings')
    op.drop_index('idx_engine_assign_container', table_name='exam_engine_assignments')
    op.drop_index('idx_engine_assign_exam',      table_name='exam_engine_assignments')
    op.drop_table('exam_engine_assignments')
    op.drop_table('engine_containers')
