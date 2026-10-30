// Early feedback for an image reference while it is typed. It follows the grammar of
// github.com/distribution/reference, which the backend checks again before every scan, so the backend
// stays the authority and this only says sooner what is wrong.
const alnum = "[a-z0-9]+";
const component = `${alnum}(?:(?:[._]|__|[-]+)${alnum})*`;
const domainComponent = "(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])";
const domain = `(?:${domainComponent}(?:\\.${domainComponent})*|\\[[a-fA-F0-9:]+\\])(?::[0-9]+)?`;
const NAME = new RegExp(`^(?:${domain}/)?${component}(?:/${component})*$`);
const TAG = /^[\w][\w.-]{0,127}$/;
const DIGEST = /^[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,}$/;
const NAME_MAX = 255;

// imageRefError returns why ref is not a valid image reference, or "" when it is (or when it is empty:
// the field's own "required" covers that). The scheme prefixes the backend strips are ignored here too.
export function imageRefError(ref) {
  let r = ref.trim();
  for (const p of ["docker://", "https://", "http://"]) if (r.startsWith(p)) r = r.slice(p.length);
  if (!r) return "";
  if (/\s/.test(r)) return "An image reference cannot contain spaces.";

  let rest = r;
  let digest = "";
  const at = rest.indexOf("@");
  if (at >= 0) {
    digest = rest.slice(at + 1);
    rest = rest.slice(0, at);
  }
  let tag = "";
  let hasTag = false;
  const colon = rest.lastIndexOf(":");
  if (colon > rest.lastIndexOf("/")) {
    hasTag = true;
    tag = rest.slice(colon + 1);
    rest = rest.slice(0, colon);
  }

  if (!rest) return "The repository is missing, e.g. docker.io/library/nginx.";
  if (rest.length > NAME_MAX) return "The repository name is too long.";
  if (!NAME.test(rest)) {
    return /[A-Z]/.test(rest.slice(rest.indexOf("/") + 1))
      ? "Repository names must be lowercase."
      : "Not a valid repository name. Use lowercase letters, digits and . _ - separated by /.";
  }
  if (hasTag && !TAG.test(tag))
    return tag ? "Not a valid tag. Use letters, digits, _ . - and at most 128 characters." : "The tag after : is empty.";
  if (at >= 0 && !DIGEST.test(digest)) return "Not a valid digest. Expected algorithm:hex, e.g. sha256:" + "0123abcd".repeat(8) + ".";
  return "";
}
