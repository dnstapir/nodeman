from namesgenerator import get_random_name as _get_random_name, left, right

ALL_NAMES = [left[li] + "-" + right[ri] for ri in range(0, len(right)) for li in range(0, len(left))]


def get_random_name() -> str:
    return str(_get_random_name(sep="-"))


def get_deterministic_name(idx: int) -> str:
    if idx > len(ALL_NAMES):
        raise IndexError
    return ALL_NAMES[idx]


if __name__ == "__main__":
    print(get_random_name())
