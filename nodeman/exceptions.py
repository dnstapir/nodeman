from fastapi_problem.error import BadRequestProblem, ConflictProblem, NotFoundProblem, StatusProblem


class UnauthorizedProblem(StatusProblem):
    status = 401


class ForbiddenProblem(StatusProblem):
    status = 403


class NotAcceptedProblem(StatusProblem):
    status = 406


class NodeNotFound(NotFoundProblem):
    title = "Node not found"


class CertificateNotFound(NotFoundProblem):
    title = "Certificate not found"


class CertificateRequestRefused(BadRequestProblem):
    title = "Certificate request refused"


class NodeAlreadyExists(ConflictProblem):
    title = "Node already exists"


class NodeNotActivated(BadRequestProblem):
    title = "Node not activated"


class NodeAlreadyEnrolled(BadRequestProblem):
    title = "Node already enrolled"


class NodeEnrollmentFailed(BadRequestProblem):
    title = "Node enrollment failed"


class NodeEnrollmentExpired(BadRequestProblem):
    title = "Node enrollment expired"


class InvalidEnrollmentSignature(UnauthorizedProblem):
    title = "Invalid enrollment signature"


class InvalidDataSignature(UnauthorizedProblem):
    title = "Invalid data signature"


class InvalidDataName(ForbiddenProblem):
    title = "Invalid data name"


class InvalidNodeName(BadRequestProblem):
    title = "Invalid node name"


class InvalidNodeTag(BadRequestProblem):
    title = "Invalid node tag"


class InvalidCertificateLifetime(BadRequestProblem):
    title = "Invalid certificate lifetime (must be > 0)"


class CertificateIssuingError(BadRequestProblem):
    title = "Error issuing certificate"


class UnsupportedPublicKeyFormat(NotAcceptedProblem):
    title = "Unsupported public key format"


class InvalidCertificateSigningRequest(BadRequestProblem):
    title = "Invalid CSR"
