# from app.db import models
# from app.db.enums import SessionStatus
# from fastapi import HTTPException

# def enforce_exam_device(user, device_id, db):

#     active = (
#         db.query(models.ExamSession)
#         .filter(
#             models.ExamSession.user_id == user.id,
#             models.ExamSession.status == SessionStatus.ACTIVE.value
#         )
#         .first()
#     )

#     if not active:
#         return

#     if active.device_fingerprint != device_id:
#         raise HTTPException(
#             403,
#             "Another device is in active exam"
#         )
