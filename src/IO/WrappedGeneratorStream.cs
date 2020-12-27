using System;
using System.IO;

namespace InflatablePalace.IO
{
    class WrappedGeneratorStream : FilterStream
    {
        Action<Stream> close;

        public WrappedGeneratorStream(
            Stream str,
            Action<Stream> close)
            : base(str)
        {
            this.close = close;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                close(this);
                return;
            }
            base.Dispose(disposing);
        }
    }
}
