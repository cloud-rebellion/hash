export type RecipientDraft = { editingId: string | null; name: string; email: string; role: string; locale: string };
export function sameRecipientDraft(left: RecipientDraft, right: RecipientDraft): boolean {
  return left.editingId === right.editingId && left.name === right.name && left.email === right.email
    && left.role === right.role && left.locale === right.locale;
}
