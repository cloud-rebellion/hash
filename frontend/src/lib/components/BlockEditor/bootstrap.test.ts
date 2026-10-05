import { expect, test } from 'bun:test';
import * as Y from 'yjs';
import { bootstrapIfGranted, shouldBootstrap } from './bootstrap';

test('fresh collaboration document permits canonical bootstrap', () => {
 const doc=new Y.Doc();expect(shouldBootstrap(doc)).toBe(true);doc.destroy();
});

test('simultaneous fresh clients converge on one canonical seed', () => {
 const owner = new Y.Doc(); const follower = new Y.Doc();
 const seed = (doc: Y.Doc) => () => doc.getXmlFragment('default').insert(0, [new Y.XmlElement('paragraph')]);
 expect(bootstrapIfGranted(follower, false, seed(follower))).toBe(false);
 expect(bootstrapIfGranted(owner, true, seed(owner))).toBe(true);
 Y.applyUpdate(follower, Y.encodeStateAsUpdate(owner));
 Y.applyUpdate(owner, Y.encodeStateAsUpdate(follower));
 expect(bootstrapIfGranted(owner, true, seed(owner))).toBe(false);
 expect(bootstrapIfGranted(follower, true, seed(follower))).toBe(false);
 expect(owner.getXmlFragment('default').length).toBe(1);
 expect(follower.getXmlFragment('default').length).toBe(1);
 owner.destroy(); follower.destroy();
});

test('reassigned grant seeds a fresh successor but never resurrects deleted history', () => {
 const successor = new Y.Doc();
 const seed = () => successor.getXmlFragment('default').insert(0, [new Y.XmlElement('paragraph')]);
 expect(bootstrapIfGranted(successor, false, seed)).toBe(false);
 expect(bootstrapIfGranted(successor, true, seed)).toBe(true);
 successor.getXmlFragment('default').delete(0, 1);
 expect(bootstrapIfGranted(successor, true, seed)).toBe(false);
 expect(successor.getXmlFragment('default').length).toBe(0);
 successor.destroy();
});
test('deleted content and its persisted replay do not resurrect canonical seed', () => {
 const doc=new Y.Doc();const fragment=doc.getXmlFragment('default');
 fragment.insert(0,[new Y.XmlElement('paragraph')]);
 expect(shouldBootstrap(doc)).toBe(false);
 fragment.delete(0,fragment.length);
 expect(fragment.length).toBe(0);expect(shouldBootstrap(doc)).toBe(false);
 const reconnected=new Y.Doc();Y.applyUpdate(reconnected,Y.encodeStateAsUpdate(doc));
 expect(reconnected.getXmlFragment('default').length).toBe(0);
 expect(shouldBootstrap(reconnected)).toBe(false);
 doc.destroy();reconnected.destroy();
});
