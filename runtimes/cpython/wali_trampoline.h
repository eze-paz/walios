/* walios branch of Include/internal/pycore_emscripten_trampoline.h (build.sh copies this
 * next to it and puts it in front of the Emscripten one): the same four call sites go
 * through _PyWali_TrampolineCall (wali_trampoline.c). */

PyObject *_PyWali_TrampolineCall(PyCFunctionWithKeywords func, PyObject *self,
                                 PyObject *args, PyObject *kw);

#define _PyCFunction_TrampolineCall(meth, self, args) \
    _PyWali_TrampolineCall(*_PyCFunctionWithKeywords_CAST(meth), (self), (args), NULL)

#define _PyCFunctionWithKeywords_TrampolineCall(meth, self, args, kw) \
    _PyWali_TrampolineCall((meth), (self), (args), (kw))

#define descr_set_trampoline_call(set, obj, value, closure)                   \
    ((int)(intptr_t)_PyWali_TrampolineCall(_PyCFunctionWithKeywords_CAST(set), \
                                           (obj), (value), (PyObject*)(closure)))

#define descr_get_trampoline_call(get, obj, closure)                  \
    _PyWali_TrampolineCall(_PyCFunctionWithKeywords_CAST(get), (obj), \
                           (PyObject*)(closure), NULL)
