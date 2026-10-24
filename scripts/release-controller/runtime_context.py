"""Only the authenticated, capability-issued control context may authorize use."""
from pathlib import Path
import hashlib,marshal,sys,types,re,os,contextlib,stat
CONTROL_SHA256='7401cd8938d4fc5b0d49401bbfac2141da4249b68dc65bd0d668aaf3f9ad3f28'
def active():
    path=Path(__file__).absolute().with_name('control.py')
    code=path.read_bytes()
    if hashlib.sha256(code).hexdigest()!=CONTROL_SHA256:raise ValueError('CONTROL_IDENTITY')
    module=sys.modules.get('control')
    if module is None or Path(getattr(module,'__file__','')).absolute()!=path:
        raise ValueError('EXTERNAL_BOOTSTRAP_REQUIRED')
    expected=next(c for c in compile(code,str(path),'exec').co_consts if isinstance(c,types.CodeType) and c.co_name=='active')
    function=getattr(module,'active',None)
    # Code-object equality compares code/constants/names structurally. Marshal
    # byte encodings also include intern/reference flags and are not a stable
    # equality representation across compilations in a running interpreter.
    if not isinstance(function,types.FunctionType) or function.__globals__ is not module.__dict__ or function.__code__!=expected:
        raise ValueError('CONTROL_MODULE_SHADOWED')
    return function()

def helper(name):
    """Load authenticated source, never execution-data imports or Python caches."""
    ctx=active()
    if not re.fullmatch('[a-z][a-z0-9_]*',name):raise ValueError('HELPER_NAME')
    root=Path(ctx.document['repositoryRoot'])/'scripts/release-controller'
    path=root/(name+'.py');expected=ctx.code_hash(name+'.py')
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('HELPER_IDENTITY')
    old=sys.modules.get(name)
    if old is not None:
        if Path(getattr(old,'__file__','')).absolute()!=path or getattr(old,'_AUTHENTICATED_SOURCE_SHA256',expected)!=expected:
            raise ValueError('HELPER_CACHE_ORIGIN')
        # Never execute cached bytecode or trust a cached module implementation.
        # Normal authenticated imports and this loader may occur in either order;
        # recompile the same verified source rather than selecting a cache winner.
    module=types.ModuleType(name);module.__file__=str(path)
    sys.modules[name]=module
    try:exec(compile(raw,str(path),'exec'),module.__dict__)
    except BaseException:
        sys.modules.pop(name,None);raise
    module._AUTHENTICATED_SOURCE_SHA256=expected
    ctx.revalidate()
    return module

def authority_document(name):
    ctx=active();module=sys.modules['control']
    return module.load(module.record(ctx.authority(name)))

def run_scanner(data,stdout,stderr):
    """Only the existing scanner in this authenticated isolated process.
    No subprocess can reconstruct or self-issue the operator capability.
    Individual scanner/tool processes retain their original bounded captures.
    """
    ctx=active();ctx.require_phase('native-linux-execution')
    if sys.platform!='linux' or os.getuid()!=1000:raise ValueError('Approved unprivileged Linux scanner required')
    profile=ctx.profile();layout=profile['bindings'].get('nativeDataLayout')
    if layout not in ('.','data'):raise ValueError('Explicit native data layout required')
    expected=Path(profile['executionRoot'])/layout
    if Path(data).absolute()!=expected.absolute():raise ValueError('Scanner execution data identity')
    for part in (expected.absolute(),*expected.absolute().parents):
        state=part.lstat()
        if stat.S_ISLNK(state.st_mode) or getattr(state,'st_file_attributes',0)&0x400:raise ValueError('Linked scanner execution data')
    if not expected.is_dir():raise ValueError('Scanner data directory required')
    code=Path(__file__).absolute().with_name('scan-images.py');control=sys.modules['control']
    raw=control.read(code)
    if hashlib.sha256(raw).hexdigest()!=ctx.code_hash('scan-images.py'):raise ValueError('Scanner source identity')
    # Imports resolve only through the already authenticated canonical graph.
    helper('qualification_evidence')
    before=os.umask(0o077)
    try:
        with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
            try:exec(compile(raw,str(code),'exec'),{'__file__':str(code),'__name__':'authenticated_native_scanner'})
            except SystemExit as error:
                return error.code if type(error.code) is int else 0 if error.code is None else 1
        return 0
    finally:os.umask(before)
