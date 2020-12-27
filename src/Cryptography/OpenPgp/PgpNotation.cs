using System;

namespace InflatablePalace.Cryptography.OpenPgp
{
    public class PgpNotation
    {
        private string name;
        private string value;
        private bool isHumanReadable;

        public PgpNotation(string name, string value, bool isHumanReadable)
        {
            if (name == null)
                throw new ArgumentNullException(nameof(name));
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            this.name = name;
            this.value = value;
            this.isHumanReadable = isHumanReadable;
        }

        public string Name => name;

        public string Value => value;

        public bool IsHumanReadable => isHumanReadable;
    }
}
