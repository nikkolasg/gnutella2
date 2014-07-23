using System;

namespace tuto
{
	public abstract class EmptyClass
	{
		public int v1;
		public int v2;
		public EmptyClass (int v1, int v2) : this(v1)
		{

			this.v2 = v2;
		}
		public EmptyClass(int v1){
			this.v1 = v1;
		}
		public override string ToString ()
		{
			return string.Format ("v1="+v1+" | v2="+v2);
		}
	}

	public class SubEmptyClass : EmptyClass {
		public int v3;
		public SubEmptyClass(int v1,int v2, int v3) : base(v1,v2) {
			this.v3 = v3;
		}
		public override string ToString ()
		{
			return base.ToString () + " | v3 = " + v3.ToString ();
		}
	}
}

